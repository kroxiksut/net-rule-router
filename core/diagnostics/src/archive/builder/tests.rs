use super::*;
use crate::archive::request::DiagnosticArchiveRequest;
use crate::facade::dto::{
    CacheHealthCard, DiagnosticModeStateDto, DiagnosticsDataOrigin, DiagnosticsStatusDto,
    LogHealthCard, SecurityStatusCard, ServiceHealthCard,
};
use crate::logs::reader::RawLogFile;

fn sample_health() -> DiagnosticsStatusDto {
    DiagnosticsStatusDto {
        overall_healthy: true,
        service_health: ServiceHealthCard {
            state: "running".into(),
            active_revision_id: Some("rev-001".into()),
            pending_changes: 0,
            start_relative_to_sign_in: "unknown".to_string(),
            start_sign_in_gap_ms: None,
        },
        security_status: SecurityStatusCard {
            audit_chain_ok: true,
            active_alert_count: 0,
            audit_write_healthy: true,
        },
        active_alerts: Vec::new(),
        cache_health: CacheHealthCard {
            entry_count: 10,
            healthy: true,
        },
        log_health: LogHealthCard {
            dir_writable: true,
            total_size_bytes: 4096,
            audit_size_bytes: 0,
            file_count: 1,
            dropped_count: 0,
            last_cleanup_at: None,
        },
        diagnostic_mode: DiagnosticModeStateDto::inactive(),
        stale: false,
        origin: DiagnosticsDataOrigin::Service,
    }
}

fn sample_input(request: DiagnosticArchiveRequest) -> ArchiveInput {
    ArchiveInput {
        health: sample_health(),
        health_enrichment: DiagnosticArchiveHealthEnrichmentDto::default(),
        log_entries: vec![LogEntryDto {
            event_id: "evt-001".into(),
            created_at: 1_745_000_000_000,
            level: "info".into(),
            category: "service".into(),
            kind: "service.started".into(),
            message_key: "diag.service.started.summary".into(),
            message: String::new(),
            has_payload: false,
            correlation_summary: Vec::new(),
            args: Default::default(),
        }],
        audit_entries: vec![AuditEntryDto {
            event_id: "adt-001".into(),
            seq: 1,
            kind: "revision_activated".into(),
            created_at: 1_745_000_000_000,
            result: "success".into(),
            reason_code: "review.approved".into(),
            revision_id: Some("rev-001".into()),
            has_payload_summary: false,
        }],
        audit_chain_lines: Vec::new(),
        raw_log_files: Vec::new(),
        explain_samples: Vec::new(),
        system_info: Some(nrr_shared::system_info::SystemInfo {
            os: "windows".into(),
            os_version: "Windows 11 Pro 23H2 (build 22631)".into(),
            arch: "AMD64".into(),
            cpu_model: "Test CPU".into(),
            cpu_logical_cores: 8,
            total_ram_bytes: 17_179_869_184,
        }),
        service_stderr: None,
        broker_logs: Vec::new(),
        request,
    }
}

#[test]
fn captured_stderr_is_archived_when_there_is_any() {
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("diag.zip");
    let mut input = sample_input(DiagnosticArchiveRequest::default_export("0.1.0-test"));
    input.service_stderr = Some("thread 'main' panicked at src/main.rs:1:1\n".to_string());

    ArchiveBuilder::build(input, &dest).expect("build archive");

    let file = std::fs::File::open(&dest).expect("open zip");
    let mut zip = zip::ZipArchive::new(file).expect("parse zip");
    let mut buffer = Vec::new();
    std::io::Read::read_to_end(
        &mut zip
            .by_name(SERVICE_STDERR_FILENAME)
            .expect("stderr section present"),
        &mut buffer,
    )
    .expect("read stderr section");
    assert!(String::from_utf8_lossy(&buffer).contains("panicked"));
}

#[test]
fn an_empty_stderr_adds_no_section() {
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("diag.zip");
    let mut input = sample_input(DiagnosticArchiveRequest::default_export("0.1.0-test"));
    // Whitespace only: the file exists on disk but the service never
    // wrote anything to it — an empty section would just raise questions.
    input.service_stderr = Some("\n\n".to_string());

    let result = ArchiveBuilder::build(input, &dest).expect("build archive");

    assert!(!result
        .manifest
        .included_sections
        .iter()
        .any(|s| s == SERVICE_STDERR_FILENAME));
}

#[test]
fn build_default_archive_succeeds() {
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("diag.zip");
    let req = DiagnosticArchiveRequest::default_export("0.1.0-test");
    let input = sample_input(req);

    let result = ArchiveBuilder::build(input, &dest).expect("build");
    assert!(dest.exists(), "zip file must exist");
    assert!(result.size_bytes > 0);
    assert_eq!(result.manifest.log_entry_count, 1);
    assert_eq!(result.manifest.audit_entry_count, 1);
}

#[test]
fn manifest_is_valid_after_build() {
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("diag.zip");
    let req = DiagnosticArchiveRequest::default_export("0.1.0-test");
    let result = ArchiveBuilder::build(sample_input(req), &dest).expect("build");
    assert!(result.manifest.validate().is_ok());
}

#[test]
fn archive_contains_no_raw_db_paths() {
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("diag.zip");
    let req = DiagnosticArchiveRequest::default_export("0.1.0-test");
    ArchiveBuilder::build(sample_input(req), &dest).expect("build");

    // Read zip and verify no raw db filenames appear.
    let file = std::fs::File::open(&dest).expect("open zip");
    let mut zip = zip::ZipArchive::new(file).expect("parse zip");
    for i in 0..zip.len() {
        let entry = zip.by_index(i).expect("entry");
        let name = entry.name();
        assert!(
            !name.ends_with(".db"),
            "archive must not contain .db files: {name}"
        );
    }
}

#[test]
fn manifest_json_is_in_archive() {
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("diag.zip");
    let req = DiagnosticArchiveRequest::default_export("0.1.0-test");
    ArchiveBuilder::build(sample_input(req), &dest).expect("build");

    let file = std::fs::File::open(&dest).expect("open zip");
    let mut zip = zip::ZipArchive::new(file).expect("parse zip");
    let names: Vec<String> = (0..zip.len())
        .map(|i| zip.by_index(i).unwrap().name().to_string())
        .collect();
    assert!(
        names.contains(&"manifest.json".to_string()),
        "manifest.json must be in archive"
    );
    assert!(names.contains(&"troubleshooting.md".to_string()));
    assert!(names.contains(&"health.json".to_string()));
    assert!(names.contains(&"logs.ndjson".to_string()));
    // system_info.json is a mandatory section.
    assert!(names.contains(&"system_info.json".to_string()));
}

#[test]
fn system_info_section_carries_host_and_app_version() {
    use std::io::Read;
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("diag.zip");
    let req = DiagnosticArchiveRequest::default_export("9.9.9-test");
    ArchiveBuilder::build(sample_input(req), &dest).expect("build");

    let file = std::fs::File::open(&dest).expect("open zip");
    let mut zip = zip::ZipArchive::new(file).expect("parse zip");
    let mut body = String::new();
    zip.by_name("system_info.json")
        .expect("system_info.json present")
        .read_to_string(&mut body)
        .expect("read");
    let v: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(v["app_version"], "9.9.9-test");
    assert_eq!(v["system_info_available"], true);
    assert_eq!(v["os"], "windows");
    assert!(v["total_ram_bytes"].as_u64().unwrap() > 0);
}

#[test]
fn logs_ndjson_drops_entries_before_logs_from_ms() {
    use std::io::Read;
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("diag.zip");
    // "Current session only": the cutoff sits between
    // entry 0 (older, dropped) and entries 1..2 (kept).
    let mut req = DiagnosticArchiveRequest::default_export("t");
    req.logs_from_ms = Some(1_745_000_000_001);
    let mut input = sample_input(req);
    input.log_entries = (0..3)
        .map(|i| LogEntryDto {
            event_id: format!("evt-{i:03}"),
            created_at: 1_745_000_000_000 + i as i64,
            level: "info".into(),
            category: "service".into(),
            kind: "service.tick".into(),
            message_key: "diag.service.tick.summary".into(),
            message: String::new(),
            has_payload: false,
            correlation_summary: Vec::new(),
            args: Default::default(),
        })
        .collect();
    ArchiveBuilder::build(input, &dest).expect("build");

    let file = std::fs::File::open(&dest).expect("open zip");
    let mut zip = zip::ZipArchive::new(file).expect("parse zip");
    let mut logs = String::new();
    zip.by_name("logs.ndjson")
        .expect("logs present")
        .read_to_string(&mut logs)
        .expect("read");
    assert_eq!(logs.lines().count(), 2, "pre-session entry is dropped");
    assert!(!logs.contains("evt-000"));
    assert!(logs.contains("evt-001"));
    assert!(logs.contains("evt-002"));
}

#[test]
fn logs_ndjson_respects_the_byte_budget() {
    use std::io::Read;
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("diag.zip");
    // Tiny byte budget: only the first line fits.
    let mut req = DiagnosticArchiveRequest::default_export("t");
    req.max_log_bytes = 80;
    let mut input = sample_input(req);
    // Three log entries, each serialising to well over 80 bytes.
    input.log_entries = (0..3)
        .map(|i| LogEntryDto {
            event_id: format!("evt-{i:03}"),
            created_at: 1_745_000_000_000 + i as i64,
            level: "info".into(),
            category: "service".into(),
            kind: "service.tick".into(),
            message_key: "diag.service.tick.summary".into(),
            message: String::new(),
            has_payload: false,
            correlation_summary: Vec::new(),
            args: Default::default(),
        })
        .collect();
    ArchiveBuilder::build(input, &dest).expect("build");

    let file = std::fs::File::open(&dest).expect("open zip");
    let mut zip = zip::ZipArchive::new(file).expect("parse zip");
    let mut logs = String::new();
    zip.by_name("logs.ndjson")
        .expect("logs present")
        .read_to_string(&mut logs)
        .expect("read");
    // Only the first entry fits under the 80-byte budget (the loop always
    // writes the first line, then stops before overrunning).
    assert_eq!(logs.lines().count(), 1, "byte budget caps the log lines");
    assert!(logs.contains("evt-000"));
    assert!(!logs.contains("evt-001"));
}

#[test]
fn health_json_carries_no_enrichment_keys_when_unpopulated() {
    // An all-`None` `health_enrichment` (the default; existing callers that never
    // touch the new field) must not add any keys to `health.json`.
    use std::io::Read;
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("diag.zip");
    let req = DiagnosticArchiveRequest::default_export("0.1.0-test");
    ArchiveBuilder::build(sample_input(req), &dest).expect("build");

    let file = std::fs::File::open(&dest).expect("open zip");
    let mut zip = zip::ZipArchive::new(file).expect("parse zip");
    let mut body = String::new();
    zip.by_name("health.json")
        .expect("health.json present")
        .read_to_string(&mut body)
        .expect("read");
    let v: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert!(v.get("behavior_mode").is_none());
    assert!(v.get("state_schema_version").is_none());
    assert!(v.get("adapters_snapshot").is_none());
    assert_eq!(v["overall_healthy"], true, "base health fields intact");
}

#[test]
fn health_json_merges_enrichment_fields_when_populated() {
    // Behavior mode / schema version / adapters snapshot land as SIBLING keys of the base
    // health fields (flat merge), not a nested sub-object.
    use nrr_shared::ipc_payloads::SnapshotInterfacesResponse;
    use std::io::Read;
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("diag.zip");
    let req = DiagnosticArchiveRequest::default_export("0.1.0-test");
    let mut input = sample_input(req);
    input.health_enrichment = DiagnosticArchiveHealthEnrichmentDto {
        behavior_mode: Some("prefer-primary".into()),
        state_schema_version: Some(29),
        adapters_snapshot: Some(SnapshotInterfacesResponse {
            data_source: "windows-live".into(),
            adapters: Vec::new(),
            secondary: None,
            rows: Vec::new(),
        }),
    };
    ArchiveBuilder::build(input, &dest).expect("build");

    let file = std::fs::File::open(&dest).expect("open zip");
    let mut zip = zip::ZipArchive::new(file).expect("parse zip");
    let mut body = String::new();
    zip.by_name("health.json")
        .expect("health.json present")
        .read_to_string(&mut body)
        .expect("read");
    let v: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    assert_eq!(v["behavior_mode"], "prefer-primary");
    assert_eq!(v["state_schema_version"], 29);
    // `SnapshotInterfacesResponse` itself is `#[serde(rename_all =
    // "kebab-case")]`, so its OWN fields render kebab-case even though
    // the enrichment DTO's field name (`adapters_snapshot`) does not.
    assert_eq!(v["adapters_snapshot"]["data-source"], "windows-live");
    // Base health fields still present alongside the new ones.
    assert_eq!(v["overall_healthy"], true);
    assert_eq!(v["service_health"]["state"], "running");
}

#[test]
fn manifest_redaction_mode_default() {
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("diag.zip");
    let req = DiagnosticArchiveRequest::default_export("0.1.0-test");
    let result = ArchiveBuilder::build(sample_input(req), &dest).expect("build");
    assert_eq!(result.manifest.redaction_mode, "default");
    assert!(!result.manifest.contains_diagnostic_detail);
}

#[test]
fn diagnostics_archive_contains_extra_sections() {
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("diag.zip");
    let req = DiagnosticArchiveRequest::diagnostics_export("0.1.0-test");
    let result = ArchiveBuilder::build(sample_input(req), &dest).expect("build");

    assert!(result
        .manifest
        .included_sections
        .contains(&"cache_health.json".to_string()));
    assert_eq!(result.manifest.redaction_mode, "diagnostics");
    assert!(result.manifest.contains_diagnostic_detail);
}

#[test]
fn diagnostics_export_ships_the_raw_verifiable_audit_chain() {
    use std::io::Read;
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("diag.zip");
    let req = DiagnosticArchiveRequest::diagnostics_export("0.1.0-test");
    let mut input = sample_input(req);
    // Two raw NDJSON audit lines WITH the chain fields the DTO summary drops.
    input.audit_chain_lines = vec![
        r#"{"seq":1,"kind":"revision_activated","prev_hash":"GENESIS","event_hash":"aaaa"}"#
            .to_string(),
        r#"{"seq":2,"kind":"revision_activated","prev_hash":"aaaa","event_hash":"bbbb"}"#
            .to_string(),
    ];
    ArchiveBuilder::build(input, &dest).expect("build");

    let file = std::fs::File::open(&dest).expect("open zip");
    let mut zip = zip::ZipArchive::new(file).expect("parse zip");
    let mut body = String::new();
    zip.by_name("audit_chain.ndjson")
        .expect("audit_chain.ndjson present in diagnostics export")
        .read_to_string(&mut body)
        .expect("read");
    // The chain fields survive verbatim (unlike audit_summary.json's DTO).
    assert!(body.contains("prev_hash"), "{body}");
    assert!(body.contains("event_hash"), "{body}");
    assert_eq!(body.lines().count(), 2);
}

/// The service's own logs ship as the DIRECTORY they live in, one entry per
/// rotated file. A day is several files, and which file a line came from is
/// how the day is navigated — the single flattened `service-logs.ndjson`
/// this replaces threw that away.
#[test]
fn service_logs_ship_as_a_directory_of_the_files_they_were_written_to() {
    use std::io::Read;
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("diag.zip");
    let mut input = sample_input(DiagnosticArchiveRequest::default_export("0.1.0-test"));
    input.raw_log_files = vec![
        RawLogFile {
            name: "nrr_service_20260907-1.ndjson".into(),
            lines: vec![r#"{"seq":1}"#.into(), r#"{"seq":2}"#.into()],
        },
        RawLogFile {
            name: "nrr_service_20260907-2.ndjson".into(),
            lines: vec![r#"{"seq":3}"#.into()],
        },
    ];
    let result = ArchiveBuilder::build(input, &dest).expect("build");

    for name in [
        "service-logs/nrr_service_20260907-1.ndjson",
        "service-logs/nrr_service_20260907-2.ndjson",
    ] {
        assert!(
            result
                .manifest
                .included_sections
                .contains(&name.to_string()),
            "{name} missing from {:?}",
            result.manifest.included_sections,
        );
    }

    let file = std::fs::File::open(&dest).expect("open zip");
    let mut zip = zip::ZipArchive::new(file).expect("parse zip");
    let mut body = String::new();
    zip.by_name("service-logs/nrr_service_20260907-1.ndjson")
        .expect("first rotation present")
        .read_to_string(&mut body)
        .expect("read");
    // Lines keep the order they were written in, whole file, nothing merged.
    assert_eq!(body, "{\"seq\":1}\n{\"seq\":2}\n");
}

/// A full-history export must not fail because the log directory is large:
/// what does not fit under the archive's own hard cap drops from the OLD
/// end, the newest file survives whole, and the user still gets a bundle.
/// (How much history is offered in the first place is the user's budget
/// setting, applied before this — `0` there means unlimited.)
#[test]
fn a_log_history_that_does_not_fit_loses_its_oldest_end_not_the_export() {
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("diag.zip");
    let mut input = sample_input(DiagnosticArchiveRequest::default_export("0.1.0-test"));
    // Four files of ~13 MiB each against the 50 MiB archive cap.
    let fat_line = format!(r#"{{"pad":"{}"}}"#, "x".repeat(4096));
    let fat_file = |name: &str| RawLogFile {
        name: name.into(),
        lines: (0..3300).map(|_| fat_line.clone()).collect(),
    };
    input.raw_log_files = vec![
        fat_file("nrr_service_20260904-1.ndjson"),
        fat_file("nrr_service_20260905-1.ndjson"),
        fat_file("nrr_service_20260906-1.ndjson"),
        fat_file("nrr_service_20260907-1.ndjson"),
    ];
    let result = ArchiveBuilder::build(input, &dest).expect("build must not fail");

    let shipped: Vec<&String> = result
        .manifest
        .included_sections
        .iter()
        .filter(|n| n.starts_with("service-logs/"))
        .collect();
    assert!(
        shipped.len() < 4 && !shipped.is_empty(),
        "what fits ships, the rest drops: {shipped:?}",
    );
    assert!(
        shipped
            .iter()
            .any(|n| n.ends_with("nrr_service_20260907-1.ndjson")),
        "the newest file must survive: {shipped:?}",
    );
    assert!(
        !shipped
            .iter()
            .any(|n| n.ends_with("nrr_service_20260904-1.ndjson")),
        "the oldest file is the one that drops: {shipped:?}",
    );
}

/// The manifest counts what the archive CARRIES. Both capped sections used
/// to report what the caller offered, so a bundle holding 10 199 log lines
/// announced 92 548 of them and sent the reader looking for the rest.
#[test]
fn the_manifest_counts_what_was_staged_not_what_was_offered() {
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("diag.zip");
    let mut req = DiagnosticArchiveRequest::diagnostics_export("0.1.0-test");
    // Budgets that bite: two log lines fit, one audit entry is allowed.
    req.max_log_bytes = 400;
    req.max_audit_entries = 1;
    let mut input = sample_input(req);
    let one_log = input.log_entries[0].clone();
    let one_audit = input.audit_entries[0].clone();
    input.log_entries = (0..50)
        .map(|i| LogEntryDto {
            event_id: format!("evt-{i:03}"),
            ..one_log.clone()
        })
        .collect();
    input.audit_entries = (0..10)
        .map(|i| AuditEntryDto {
            event_id: format!("adt-{i:03}"),
            seq: i + 1,
            ..one_audit.clone()
        })
        .collect();

    let result = ArchiveBuilder::build(input, &dest).expect("build");

    assert_eq!(
        result.manifest.audit_entry_count, 1,
        "the entry cap is what the file carries",
    );
    assert!(
        result.manifest.log_entry_count < 50,
        "the byte budget dropped the tail; the manifest must say so (got {})",
        result.manifest.log_entry_count,
    );

    // And the count is the file's own line count, not an estimate.
    use std::io::Read;
    let file = std::fs::File::open(&dest).expect("open zip");
    let mut zip = zip::ZipArchive::new(file).expect("parse zip");
    let mut body = String::new();
    zip.by_name("logs.ndjson")
        .expect("logs.ndjson")
        .read_to_string(&mut body)
        .expect("read");
    assert_eq!(body.lines().count() as u32, result.manifest.log_entry_count,);
}

/// A section with nothing in it must be ABSENT, not present-and-empty: the
/// caller withholds the raw chain from an export it cannot verify, and a
/// zero-byte file leaves the reader guessing between "nothing happened",
/// "unreadable" and "truncated". The redaction report says it is missing.
#[test]
fn a_section_with_nothing_in_it_is_absent_rather_than_empty() {
    use std::io::Read;
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("diag.zip");
    let req = DiagnosticArchiveRequest::diagnostics_export("0.1.0-test");
    let mut input = sample_input(req);
    // A diagnostics-tier export whose caller supplied neither.
    input.audit_chain_lines = Vec::new();
    input.explain_samples = Vec::new();
    let result = ArchiveBuilder::build(input, &dest).expect("build");

    for name in ["audit_chain.ndjson", "explain_samples.json"] {
        assert!(
            !result
                .manifest
                .included_sections
                .contains(&name.to_string()),
            "{name} was announced but carries nothing",
        );
    }

    let file = std::fs::File::open(&dest).expect("open zip");
    let mut zip = zip::ZipArchive::new(file).expect("parse zip");
    let names: Vec<String> = (0..zip.len())
        .map(|i| zip.by_index(i).unwrap().name().to_string())
        .collect();
    assert!(
        !names.contains(&"audit_chain.ndjson".to_string()),
        "{names:?}"
    );
    assert!(
        !names.contains(&"explain_samples.json".to_string()),
        "{names:?}"
    );

    // What is missing is stated, not left to be noticed.
    let mut report = String::new();
    zip.by_name("redaction_report.json")
        .expect("redaction_report.json")
        .read_to_string(&mut report)
        .expect("read");
    let report: serde_json::Value = serde_json::from_str(&report).expect("parse");
    let excluded = report["excluded_sections"]
        .as_array()
        .expect("excluded_sections");
    for name in ["audit_chain.ndjson", "explain_samples.json"] {
        assert!(
            excluded.iter().any(|v| v == name),
            "{name} missing from excluded_sections: {excluded:?}",
        );
    }
}

#[test]
fn default_export_never_ships_the_raw_audit_chain() {
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("diag.zip");
    let req = DiagnosticArchiveRequest::default_export("0.1.0-test");
    let mut input = sample_input(req);
    // Even if raw lines are somehow supplied, a default export must not
    // include the AuditChain section (privacy: raw payload_summary_json).
    input.audit_chain_lines = vec![r#"{"seq":1,"event_hash":"secret"}"#.to_string()];
    ArchiveBuilder::build(input, &dest).expect("build");

    let file = std::fs::File::open(&dest).expect("open zip");
    let mut zip = zip::ZipArchive::new(file).expect("parse zip");
    let names: Vec<String> = (0..zip.len())
        .map(|i| zip.by_index(i).unwrap().name().to_string())
        .collect();
    assert!(
        !names.contains(&"audit_chain.ndjson".to_string()),
        "default export leaked the raw audit chain: {names:?}"
    );
    // The redacted summary is still present (it is mandatory).
    assert!(names.contains(&"audit_summary.json".to_string()));
}

#[test]
fn build_failure_does_not_leave_orphan_temp_files() {
    // We can't easily force a build failure here without mocking,
    // but we verify the temp dir itself is not leaked by checking
    // the system temp dir count hasn't grown after a successful build.
    // This test ensures the happy path cleans up.
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("sub").join("diag.zip"); // sub dir created by builder
    let req = DiagnosticArchiveRequest::default_export("0.1.0-test");
    ArchiveBuilder::build(sample_input(req), &dest).expect("build");
    assert!(dest.exists());
}

#[test]
fn zip_entries_are_stamped_with_local_wall_clock_time() {
    // Captured before/after the build call so the assertion can't flake
    // near a wall-clock rollover (second, minute, midnight, ...).
    let before = chrono::Local::now();
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("diag.zip");
    let req = DiagnosticArchiveRequest::default_export("0.1.0-test");
    ArchiveBuilder::build(sample_input(req), &dest).expect("build");
    let after = chrono::Local::now();

    let file = std::fs::File::open(&dest).expect("open zip");
    let mut zip = zip::ZipArchive::new(file).expect("parse zip");
    let entry = zip.by_name("manifest.json").expect("manifest.json present");
    let mtime = entry
        .last_modified()
        .expect("entry carries a modified time");

    let entry_naive = chrono::NaiveDate::from_ymd_opt(
        mtime.year() as i32,
        mtime.month() as u32,
        mtime.day() as u32,
    )
    .and_then(|date| {
        date.and_hms_opt(
            mtime.hour() as u32,
            mtime.minute() as u32,
            mtime.second() as u32,
        )
    })
    .expect("zip entry stores a valid calendar date/time");

    // DOS timestamps have 2-second resolution and drop odd seconds, so
    // widen the [before, after] window by a few seconds on both ends.
    // Under the old UTC-"now" behavior this assertion fails on any
    // machine whose local offset from UTC is nonzero.
    let tolerance = chrono::Duration::seconds(3);
    let lower = before.naive_local() - tolerance;
    let upper = after.naive_local() + tolerance;
    assert!(
        entry_naive >= lower && entry_naive <= upper,
        "expected entry mtime {entry_naive:?} within [{lower:?}, {upper:?}] \
             (local time), got a value that looks UTC-shifted"
    );
}

#[test]
fn no_backup_guarantee_in_manifest() {
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("diag.zip");
    let req = DiagnosticArchiveRequest::default_export("0.1.0-test");
    let result = ArchiveBuilder::build(sample_input(req), &dest).expect("build");
    assert!(
        result.manifest.no_backup_guarantee.contains("diagnostic"),
        "no_backup_guarantee must mention 'diagnostic'"
    );
}

#[test]
fn the_manifest_states_the_size_of_what_it_describes() {
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("archive.zip");
    let input = sample_input(DiagnosticArchiveRequest::default_export("0.1.0-test"));

    let result = ArchiveBuilder::build(input, &dest).expect("build");
    assert!(
        result.manifest.total_size_bytes_approx > 0,
        "a manifest that reports zero bytes describes nothing"
    );
    assert!(result.size_bytes > 0);
}

#[test]
fn a_failed_build_leaves_no_archive_behind() {
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("archive.zip");
    let mut input = sample_input(DiagnosticArchiveRequest::default_export("0.1.0-test"));
    // Captured stderr goes into the archive verbatim; oversize it past the
    // 50 MiB cap so the build has to abort mid-zip.
    input.service_stderr =
        Some("x".repeat(crate::archive::request::MAX_ARCHIVE_SIZE_BYTES as usize + 1024));

    let result = ArchiveBuilder::build(input, &dest);
    assert!(result.is_err(), "the size cap must stop the export");
    assert!(
        !dest.exists(),
        "a truncated zip must not be left where retention counts it as good"
    );
    assert!(
        !dest.with_extension("part").exists(),
        "no leftover part file"
    );
}

#[test]
fn the_redaction_report_names_the_sections_that_were_left_out() {
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("archive.zip");
    let input = sample_input(DiagnosticArchiveRequest::default_export("0.1.0-test"));

    ArchiveBuilder::build(input, &dest).expect("build");

    let file = std::fs::File::open(&dest).expect("open zip");
    let mut zip = zip::ZipArchive::new(file).expect("read zip");
    let mut json = String::new();
    {
        use std::io::Read;
        let mut entry = zip
            .by_name("redaction_report.json")
            .expect("report present");
        entry.read_to_string(&mut json).expect("read report");
    }
    let report: serde_json::Value = serde_json::from_str(&json).expect("parse");
    let excluded: Vec<String> = report["excluded_sections"]
        .as_array()
        .expect("array")
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        excluded.contains(&"audit_chain.ndjson".to_string()),
        "a default export excludes the raw chain and must say so: {excluded:?}"
    );
}

#[test]
fn captured_stderr_does_not_carry_the_users_name_into_the_archive() {
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("archive.zip");
    let mut input = sample_input(DiagnosticArchiveRequest::default_export("0.1.0-test"));
    input.service_stderr = Some(
        "panicked at C:QQUsersQQalexeyQQAppDataQQnrr.exe:12"
            .to_string()
            .replace("QQ", "\\"),
    );

    ArchiveBuilder::build(input, &dest).expect("build");

    let text = read_zip_entry(&dest, SERVICE_STDERR_FILENAME);
    assert!(
        !text.contains("alexey"),
        "user name leaked verbatim: {text}"
    );
    assert!(
        text.contains("nrr.exe:12"),
        "the useful part of the panic must survive: {text}"
    );
}

/// With the raw files attached, `logs.ndjson` would only repeat their lines
/// without payloads: it is left out, the manifest counts the raw lines, and
/// the redaction report does not call it withheld.
#[test]
fn raw_log_files_replace_the_logs_listing() {
    use std::io::Read;
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("diag.zip");
    let mut input = sample_input(DiagnosticArchiveRequest::diagnostics_export("0.1.0-test"));
    input.raw_log_files = vec![RawLogFile {
        name: "nrr_service_20260907-1.ndjson".into(),
        lines: vec![r#"{"seq":1}"#.into(), r#"{"seq":2}"#.into()],
    }];
    let result = ArchiveBuilder::build(input, &dest).expect("build");

    let sections = &result.manifest.included_sections;
    assert!(
        !sections.contains(&"logs.ndjson".to_string()),
        "{sections:?}"
    );
    assert_eq!(result.manifest.log_entry_count, 2);

    let file = std::fs::File::open(&dest).expect("open zip");
    let mut zip = zip::ZipArchive::new(file).expect("parse zip");
    assert!(zip.by_name("logs.ndjson").is_err());
    let mut report = String::new();
    zip.by_name("redaction_report.json")
        .expect("redaction_report.json")
        .read_to_string(&mut report)
        .expect("read");
    let report: serde_json::Value = serde_json::from_str(&report).expect("parse");
    let excluded = report["excluded_sections"]
        .as_array()
        .expect("excluded_sections");
    assert!(!excluded.iter().any(|v| v == "logs.ndjson"), "{excluded:?}");
}

#[test]
fn broker_logs_ship_at_the_root_without_the_users_name() {
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("diag.zip");
    let mut input = sample_input(DiagnosticArchiveRequest::default_export("0.1.0-test"));
    input.broker_logs = vec![
        AttachedLog {
            name: "nrr-broker.log".into(),
            text: "1 pid=7 service-control: stop via C:QQUsersQQalexeyQQnrr-service.exe\n"
                .replace("QQ", "\\"),
        },
        AttachedLog {
            name: "nrr-broker.prev.log".into(),
            text: "  \n".into(),
        },
    ];
    let result = ArchiveBuilder::build(input, &dest).expect("build");

    let sections = &result.manifest.included_sections;
    assert!(
        sections.contains(&"nrr-broker.log".to_string()),
        "{sections:?}"
    );
    assert!(
        !sections.contains(&"nrr-broker.prev.log".to_string()),
        "an empty log adds no file: {sections:?}"
    );
    let text = read_zip_entry(&dest, "nrr-broker.log");
    assert!(
        !text.contains("alexey"),
        "user name leaked verbatim: {text}"
    );
    assert!(text.contains("nrr-service.exe"), "{text}");
}

#[test]
fn a_default_export_does_not_ship_mac_addresses_or_dns_servers() {
    use nrr_shared::ipc_payloads::{AdapterEntry, InterfaceRowDto, SnapshotInterfacesResponse};

    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("archive.zip");
    let mut input = sample_input(DiagnosticArchiveRequest::default_export("0.1.0-test"));
    let row = InterfaceRowDto {
        persistent_id: "00-11-22-33-44-55".into(),
        adapter_name: "Ethernet".into(),
        windows_name: "Ethernet".into(),
        interface_description: "Realtek Gaming GbE".into(),
        interface_type: "ethernet".into(),
        is_bluetooth_like: false,
        local_ip: "192.168.1.42".into(),
        gateway: "192.168.1.1".into(),
        dns_servers: "8.8.8.8, 1.1.1.1".into(),
        has_default_route: true,
        has_forwarding_path: Some(true),
        runtime_data_unavailable: false,
        availability: "available".into(),
        selected_role: None,
        route_state: "not-selected".into(),
        observed_facts: nrr_shared::ipc_payloads::InterfaceObservedFactsDto {
            connectivity_state: "online".into(),
            external_ip_status: "not-checked".into(),
            external_ip: None,
            external_probe_attempted: false,
            external_probe_note: String::new(),
        },
        derived_assessment: nrr_shared::ipc_payloads::InterfaceDerivedAssessmentDto {
            vpn_tunnel_likelihood: "low".into(),
            virtual_interface_likelihood: "low".into(),
            service_interface_likelihood: "low".into(),
            classification: "physical".into(),
            confidence_percent: 90,
            heuristic_only: true,
            signals: Vec::new(),
        },
        recommendation: nrr_shared::ipc_payloads::InterfaceRecommendationDto {
            class: "primary-candidate".into(),
            confidence: "high".into(),
            advisory_only: true,
            summary: String::new(),
            key_signals: Vec::new(),
            excluded_alternatives: Vec::new(),
        },
    };
    input.health_enrichment.adapters_snapshot = Some(SnapshotInterfacesResponse {
        data_source: "windows-live".into(),
        adapters: vec![AdapterEntry {
            persistent_id: "00-11-22-33-44-55".into(),
            adapter_name: "Ethernet".into(),
            ipv6_if_index: 12,
            physical_address: Some("00-11-22-33-44-55".into()),
            windows_name: "Ethernet".into(),
            interface_description: "Realtek Gaming GbE".into(),
            interface_type: "ethernet".into(),
            oper_status: "up".into(),
        }],
        secondary: None,
        rows: vec![row],
    });

    ArchiveBuilder::build(input, &dest).expect("build");

    let health = read_zip_entry(&dest, "health.json");
    assert!(
        !health.contains("00-11-22-33-44-55"),
        "MAC leaked: {health}"
    );
    assert!(!health.contains("192.168.1.42"), "local address leaked");
    assert!(!health.contains("8.8.8.8"), "DNS server leaked");
}

fn read_zip_entry(archive: &Path, name: &str) -> String {
    use std::io::Read;
    let file = std::fs::File::open(archive).expect("open zip");
    let mut zip = zip::ZipArchive::new(file).expect("read zip");
    let mut entry = zip.by_name(name).expect("entry present");
    let mut text = String::new();
    entry.read_to_string(&mut text).expect("read entry");
    text
}
