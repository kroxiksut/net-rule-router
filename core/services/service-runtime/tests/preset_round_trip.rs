#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Cross-cutting round-trip tests for preset
//! import/export and settings export.
//!
//! These exercise the executor's `PresetImport` pipeline against the
//! production exporter, plus the settings exporter against the
//! `RouteBindingsRepository`, end-to-end on an in-memory state DB.
//!
//! Coverage:
//! - Import preset → export via `ProductionPresetExporter` → re-parse →
//!   semantic equality with the canonical baseline.
//! - Both-routes import yields one revision covering both routes.
//! - `SettingsExportFull` YAML matches docs/en/rules-file-format.md Settings Export Format (no
//!   `ui_preferences:` block).

#![cfg(target_os = "windows")]

use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use nrr_domain::rules_file::{parse_rules_file, RulesFileSection};
use nrr_service_runtime::activation_coordinator::{
    ActivationAuditEmitter, ActivationCoordinator, ApplyFailurePolicy, Clock, IdGenerator,
    RulesApplyDispatcher,
};
use nrr_service_runtime::active_sid_registry::ActiveSidRegistry;
use nrr_service_runtime::crash_recovery::ApplyMarkerStore;
use nrr_service_runtime::ipc_handlers::providers::{MutationExecutor, MutationOutcome};
use nrr_service_runtime::production_coordinator::{
    NoopRulesApplyDispatcher, ProductionApplyMarkerStore, ProductionIdGenerator,
};
use nrr_service_runtime::production_mutation_executor::ProductionMutationExecutor;
use nrr_service_runtime::production_preset_exporter::{
    PresetExportSource, ProductionPresetExporter,
};
use nrr_service_runtime::production_settings::SystemClock;
use nrr_service_runtime::production_settings_exporter::{
    ProductionSettingsExporter, SettingsExportSource,
};
use nrr_shared::ipc_payloads::MutationKind;
use nrr_shared::RouteRole;
use nrr_storage::migration::SqliteMigrationRunner;
use nrr_storage::repository::MigrationRunner;
use nrr_storage::route_bindings::{
    BehaviorMode, BindingSource, RouteBindingRecord, RouteBindingsRepository, RoutePolicyRecord,
};
use rusqlite::Connection;

// ── Fixture ──────────────────────────────────────────────────────────────────

fn open_state_db() -> Arc<Mutex<Connection>> {
    let conn = Connection::open_in_memory().expect("open in-memory state DB");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("state migrations");
    Arc::new(Mutex::new(runner.into_connection()))
}

struct NoopActivationAudit;
impl ActivationAuditEmitter for NoopActivationAudit {
    fn emit(&self, _: nrr_service_runtime::activation_coordinator::ActivationAuditEvent) {}
}

// Unique apply-marker dir under the cargo target tmp dir (NOT the shared
// system temp). Using `std::env::temp_dir()` collided with marker files the
// real service writes there as LocalSystem — the test process then can't
// remove them (access denied, os error 5). `CARGO_TARGET_TMPDIR` is per-
// package and `cargo clean`-able; the atomic counter isolates parallel tests.
fn unique_marker_dir() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "preset_round_trip_markers_{}",
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("create unique marker dir");
    dir
}

fn build_executor(
    state_conn: Arc<Mutex<Connection>>,
) -> (ProductionMutationExecutor, Arc<ActivationCoordinator>) {
    let marker_store = Arc::new(ProductionApplyMarkerStore::new(&unique_marker_dir()))
        as Arc<dyn ApplyMarkerStore>;
    let dispatcher = Arc::new(NoopRulesApplyDispatcher) as Arc<dyn RulesApplyDispatcher>;
    let id_gen = Arc::new(ProductionIdGenerator::new()) as Arc<dyn IdGenerator>;
    let coordinator = Arc::new(ActivationCoordinator::new(
        Arc::clone(&state_conn),
        Arc::new(ActiveSidRegistry::new()),
        dispatcher,
        marker_store,
        Arc::new(NoopActivationAudit) as Arc<dyn ActivationAuditEmitter>,
        Arc::new(SystemClock) as Arc<dyn Clock>,
        id_gen,
        ApplyFailurePolicy::AllOrNothing,
    ));
    let executor = ProductionMutationExecutor::new(Arc::clone(&coordinator))
        .with_state_conn(Arc::clone(&state_conn));
    (executor, coordinator)
}

fn b64(text: &str) -> String {
    BASE64_STANDARD.encode(text.as_bytes())
}

fn decode_b64(s: &str) -> String {
    String::from_utf8(BASE64_STANDARD.decode(s.as_bytes()).expect("decode")).expect("utf8")
}

// ── Round-trip: import preset → export → semantic equal ──────────────────────

#[test]
fn import_preset_then_export_round_trips_semantically() {
    let conn = open_state_db();
    let (executor, _coord) = build_executor(Arc::clone(&conn));

    let preset_text = "\
--- Zones
ru

--- Domains
example.com
*.corp.example.net  # all subdomains
# old.example.com  # decommissioned

--- IP
203.0.113.7

--- Windows
chrome.exe
";

    let payload = serde_json::json!({
        "primary-bytes-b64": b64(preset_text),
        "include-child-processes": false,
        "correlation-id": "round-trip-1",
    });
    let stored = nrr_service_runtime::ipc_handlers::mutation_token_store::StoredMutation {
        kind: MutationKind::PresetImport,
        payload,
        correlation_id: Some("round-trip-1".to_string()),
        issuer_sid: String::new(),
        caller_is_elevated: true,
    };
    let outcome = executor.execute(stored, nrr_storage::BASELINE_PRINCIPAL);
    assert!(
        matches!(outcome, MutationOutcome::Completed(_)),
        "executor.execute must succeed; got {outcome:?}"
    );

    // Now export and parse the bytes back. The round-trip semantic
    // equality is: every (enabled, address-value-or-app-value, comment)
    // tuple appears on both sides; ordering may differ because the
    // canonical sort places `ExactFqdn → SuffixDomain → Zone → IP → App`
    // whereas the file lists `Zones → Domains → IP → Windows`.
    let exporter = ProductionPresetExporter::new(Arc::clone(&conn))
        .with_host_app_section(RulesFileSection::Windows);
    let out = exporter
        .export_rules_file(nrr_storage::BASELINE_PRINCIPAL, RouteRole::Primary, false)
        .expect("export");

    // Original preset has 6 entries; exported parse must have the same
    // count (one disabled, five enabled) on the primary route.
    let parsed_orig = parse_rules_file(preset_text).parsed;
    let parsed_back = parse_rules_file(&out.file_bytes_utf8).parsed;
    let total_orig: usize = parsed_orig.sections.iter().map(|s| s.entries.len()).sum();
    let total_back: usize = parsed_back.sections.iter().map(|s| s.entries.len()).sum();
    assert_eq!(
        total_orig, total_back,
        "entry count diverged\norig=\n{preset_text}\nback=\n{}",
        out.file_bytes_utf8
    );

    // Compare entry value-sets.
    let collect_values = |p: &nrr_domain::rules_file::RulesFileParsed| {
        let mut v: Vec<(bool, String, String)> = p
            .sections
            .iter()
            .flat_map(|s| {
                s.entries.iter().map(move |e| {
                    (
                        e.enabled,
                        e.match_value.clone(),
                        e.inline_comment.clone().unwrap_or_default(),
                    )
                })
            })
            .collect();
        v.sort();
        v
    };
    assert_eq!(
        collect_values(&parsed_orig),
        collect_values(&parsed_back),
        "value set diverged after round-trip"
    );
}

// ── Both-routes import yields one revision covering both routes ──────────────

#[test]
fn both_routes_import_creates_one_revision_with_both_route_rules() {
    let conn = open_state_db();
    let (executor, _coord) = build_executor(Arc::clone(&conn));

    let payload = serde_json::json!({
        "primary-bytes-b64": b64("--- Domains\nprimary.example\n"),
        "secondary-bytes-b64": b64("--- Domains\nsecondary.example\n"),
        "include-child-processes": false,
    });
    let stored = nrr_service_runtime::ipc_handlers::mutation_token_store::StoredMutation {
        kind: MutationKind::PresetImport,
        payload,
        correlation_id: None,
        issuer_sid: String::new(),
        caller_is_elevated: true,
    };
    let outcome = executor.execute(stored, nrr_storage::BASELINE_PRINCIPAL);
    assert!(matches!(outcome, MutationOutcome::Completed(_)));

    let exporter = ProductionPresetExporter::new(Arc::clone(&conn))
        .with_host_app_section(RulesFileSection::Windows);
    let primary = exporter
        .export_rules_file(nrr_storage::BASELINE_PRINCIPAL, RouteRole::Primary, false)
        .expect("export primary");
    let secondary = exporter
        .export_rules_file(nrr_storage::BASELINE_PRINCIPAL, RouteRole::Secondary, false)
        .expect("export secondary");
    assert!(primary.file_bytes_utf8.contains("primary.example"));
    assert!(!primary.file_bytes_utf8.contains("secondary.example"));
    assert!(secondary.file_bytes_utf8.contains("secondary.example"));
    assert!(!secondary.file_bytes_utf8.contains("primary.example"));
}

// ── SettingsExportFull YAML conforms to docs/en/rules-file-format.md Settings Export Format ──────────────────────

#[test]
fn settings_export_full_yaml_conforms_to_formats_md_2_4() {
    let conn = open_state_db();
    // Seed per-SID bindings so the YAML carries non-empty adapters.
    {
        let guard = conn.lock().unwrap();
        let repo = RouteBindingsRepository::new(&guard);
        let record = RoutePolicyRecord {
            primary: Some(RouteBindingRecord {
                stable_id: "mac=AA:BB:CC:DD:EE:FF;ifindex=3".to_string(),
                display_name: "Main".to_string(),
                user_confirmed: true,
                known_stable_ids: vec![],
            }),
            secondary: Some(RouteBindingRecord {
                stable_id: "mac=11:22:33:44:55:66;ifindex=7".to_string(),
                display_name: "VPN".to_string(),
                user_confirmed: true,
                known_stable_ids: vec![],
            }),
            mode: BehaviorMode::PreferPrimary,
            block_secondary_when_unavailable: false,
            kill_switch_fail_closed: true,
            kill_switch_protocols: 0x7F,
            kill_switch_block_all: false,
            kill_switch_enabled: false,
            allow_dns_over_primary: false,
            include_subdomains: false,
            shared_ip_policy: nrr_domain::shared_ip::SharedIpPolicy::default(),
            mode_a_coverage_strategy: nrr_domain::mode_a_coverage::ModeACoverageStrategy::default(),
            resolve_hosts_bypass: true,
            doh_lockdown_enabled: false,
            doh_lockdown_scope: nrr_storage::doh_lockdown::DohLockdownScope::default(),
            browser_history_auto_seed: false,
            kill_switch_strict_shared_ips: false,
            auto_rules_mode: nrr_storage::auto_rules::AutoRulesMode::default(),
            auto_rules_eager_delivery_names: false,
            binding_source: BindingSource::UserAssigned,
        };
        repo.update_for_sid("S-1-5-21-test", &record, 1)
            .expect("seed bindings");
    }

    let exporter = ProductionSettingsExporter::new(Arc::clone(&conn));
    let out = exporter
        .export_settings(
            "S-1-5-21-test",
            Some(r"C:\rules_primary.txt"),
            Some(r"C:\rules_secondary.txt"),
            "2026-05-20T12:00:00Z",
        )
        .expect("export");

    let yaml = &out.yaml_bytes_utf8;
    // Required top-level structure.
    assert!(yaml.starts_with("nrr_settings_export:\n"));
    assert!(yaml.contains("version: 1\n"));
    assert!(yaml.contains("exported_at: \"2026-05-20T12:00:00Z\"\n"));
    // adapters: block with both roles populated.
    assert!(yaml.contains("system_id: \"mac=AA:BB:CC:DD:EE:FF;ifindex=3\""));
    assert!(yaml.contains("user_label: \"Main\""));
    assert!(yaml.contains("user_confirmed: true"));
    assert!(yaml.contains("system_id: \"mac=11:22:33:44:55:66;ifindex=7\""));
    // rules_files: block with both paths (Windows backslashes escaped).
    assert!(yaml.contains(r#"primary: "C:\\rules_primary.txt""#));
    assert!(yaml.contains(r#"secondary: "C:\\rules_secondary.txt""#));
    // behavior: block with route_mode.
    assert!(yaml.contains("route_mode: \"prefer-primary\""));
    // FORBIDDEN: no ui_preferences: block (docs/en/rules-file-format.md Settings Export Format What is NOT included invariant).
    assert!(
        !yaml.contains("ui_preferences"),
        "YAML must NOT contain `ui_preferences:` block; got:\n{yaml}"
    );
    // Not yet exported: file_change_behavior / include_child_processes.
    assert!(!yaml.contains("file_change_behavior"));
    assert!(!yaml.contains("include_child_processes"));
}

// ── PresetExportGet response wire shape ──────────────────────────────────────

#[test]
fn preset_export_response_bytes_decode_to_canonical_txt() {
    let conn = open_state_db();
    let (executor, _coord) = build_executor(Arc::clone(&conn));

    let payload = serde_json::json!({
        "primary-bytes-b64": b64("--- Domains\nwire-test.example\n"),
        "include-child-processes": false,
    });
    let stored = nrr_service_runtime::ipc_handlers::mutation_token_store::StoredMutation {
        kind: MutationKind::PresetImport,
        payload,
        correlation_id: None,
        issuer_sid: String::new(),
        caller_is_elevated: true,
    };
    let outcome = executor.execute(stored, nrr_storage::BASELINE_PRINCIPAL);
    assert!(matches!(outcome, MutationOutcome::Completed(_)));

    let exporter = ProductionPresetExporter::new(Arc::clone(&conn))
        .with_host_app_section(RulesFileSection::Windows);
    let out = exporter
        .export_rules_file(nrr_storage::BASELINE_PRINCIPAL, RouteRole::Primary, false)
        .expect("export");

    // The handler wraps the bytes in base64 before sending. Round-trip
    // through encode/decode here so future wire-protocol changes that
    // affect transport will trip the integration boundary.
    let wire_b64 = BASE64_STANDARD.encode(out.file_bytes_utf8.as_bytes());
    let decoded = decode_b64(&wire_b64);
    assert!(decoded.contains("wire-test.example"));
    // content-hash deterministic + 64-hex.
    assert_eq!(out.content_hash_hex.len(), 64);
}
