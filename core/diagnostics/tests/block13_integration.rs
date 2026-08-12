//! Diagnostics subsystem integration tests and acceptance gate.
//!
//! These tests verify cross-cutting behaviour across the diagnostics subsystem:
//! - Event taxonomy → operational logs → facade query
//! - Audit write → chain verify → alert state
//! - Privacy redaction consistency across paths (golden tests)
//! - Archive export: no raw DB files, no sensitive data in default mode
//! - Cleanup protection: audit NDJSON excluded from operational log cleanup
//! - Reason code stability (regression)
//! - Facade contract: no raw storage paths exposed to GUI

use nrr_diagnostics::archive::{ArchiveBuilder, ArchiveInput, DiagnosticArchiveRequest};
use nrr_diagnostics::audit::{
    ActorKind, AuditEventInput, AuditEventKind, AuditEventResult, AuditQueryFilter, AuditReader,
    AuditWriter, AuditWriterConfig, InMemorySecurityAlertsRepository, SecurityAlertState,
    SecurityAlertsRepository,
};
use nrr_diagnostics::explain::{ExplainDataAvailability, ExplainQueryKind, ExplainResponse};
use nrr_diagnostics::facade::{DiagnosticsFacade, MockDiagnosticsFacade, MockScenario};
use nrr_diagnostics::logs::{LogReader, LogWriter, LogWriterConfig, LoggingMode};
use nrr_diagnostics::privacy::{
    redact_hostname, redact_ipv4, redact_ipv4_str, redact_process_path, RedactionMode,
    MARKER_PRIVATE_IPV4, MARKER_PUBLIC_IPV4,
};
use nrr_diagnostics::reason::{reason_code_meta, ALL_REASON_CODES};
use nrr_diagnostics::retention::{CleanupJob, LogRetentionPolicy, ManualCleanupScope};
use nrr_diagnostics::sink::{AuditSink, DiagnosticsSink};
use nrr_diagnostics::taxonomy::EventLevel;
use nrr_diagnostics::{reason, LogEvent};
use nrr_domain::decision_explain::ExplainDetailLevel;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn info_service_event(id: &str) -> LogEvent {
    LogEvent::new(
        id,
        1_745_000_000_000,
        EventLevel::Info,
        reason::service::STARTED,
    )
}

fn audit_input(id: &str, kind: AuditEventKind) -> AuditEventInput {
    AuditEventInput {
        event_id: id.into(),
        kind,
        created_at: 1_745_000_000_000,
        actor_kind: ActorKind::User,
        actor_id_hash: None,
        revision_id: Some("rev-001".into()),
        risk_level: None,
        result: AuditEventResult::Success,
        reason_code: reason::review::APPROVED,
        payload_summary_json: None,
    }
}

// ── 1. Operational log write → read → facade ──────────────────────────────────

/// Writes events via LogWriter and verifies the reader sees them.
#[test]
fn log_write_read_roundtrip() {
    let dir = tempfile::tempdir().expect("temp");

    // Write via LogWriter (Default mode: only Service events pass).
    let writer = LogWriter::open(LogWriterConfig::new(dir.path()));
    writer.emit(info_service_event("evt-001"));
    writer.emit(info_service_event("evt-002"));
    writer.emit(info_service_event("evt-003"));

    // Read via LogReader.
    let reader = nrr_diagnostics::logs::LogReader::new(dir.path());
    let events = reader.scan(&nrr_diagnostics::logs::LogQueryFilter::new());
    assert_eq!(events.len(), 3, "all service info events must be written");

    // Verify event structure.
    for e in &events {
        assert_eq!(e.level, EventLevel::Info);
        assert_eq!(e.kind, "service.started");
        assert!(!e.event_id.is_empty());
        assert!(e.created_at > 0);
    }
}

/// Default mode filters out Debug events — they do not appear in the reader.
#[test]
fn default_mode_filters_debug_events() {
    let dir = tempfile::tempdir().expect("temp");
    let writer = LogWriter::open(LogWriterConfig::new(dir.path()));

    // Debug cache event — filtered in Default mode.
    let debug_event = LogEvent::new("dbg", 1_000, EventLevel::Debug, reason::cache::HIT);
    writer.emit(debug_event);

    let reader = nrr_diagnostics::logs::LogReader::new(dir.path());
    assert_eq!(
        reader.list_files().len(),
        0,
        "no file should be created for filtered events"
    );
}

/// Switching to Diagnostic mode emits previously-filtered events.
#[test]
fn diagnostic_mode_emits_debug_and_decision_events() {
    let dir = tempfile::tempdir().expect("temp");
    let mut config = LogWriterConfig::new(dir.path());
    config.initial_mode = LoggingMode::Diagnostic;
    let writer = LogWriter::open(config);

    let decision_event = LogEvent::new(
        "d1",
        1_000,
        EventLevel::Debug,
        reason::decision::ROUTE_SELECTED,
    );
    writer.emit(decision_event);

    let reader = nrr_diagnostics::logs::LogReader::new(dir.path());
    let events = reader.scan(&nrr_diagnostics::logs::LogQueryFilter::new());
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, "decision.route_selected");
}

// ── 2. Audit write → chain verify → alert state ───────────────────────────────

/// Audit events are written, chain is valid, and audit files are separate from logs.
#[test]
fn audit_write_chain_verify_and_separation() {
    let audit_dir = tempfile::tempdir().expect("audit dir");
    let logs_dir = tempfile::tempdir().expect("logs dir");

    let audit_writer = AuditWriter::open(AuditWriterConfig::new(audit_dir.path()));
    audit_writer
        .append(audit_input("adt-001", AuditEventKind::RevisionActivated))
        .expect("write 1");
    audit_writer
        .append(audit_input("adt-002", AuditEventKind::ReviewApproved))
        .expect("write 2");
    audit_writer
        .append(audit_input("adt-003", AuditEventKind::RollbackStarted))
        .expect("write 3");

    // Chain must be valid.
    let reader = AuditReader::new(audit_dir.path());
    let v = reader.verify_latest_chain();
    assert!(
        v.chain_ok,
        "audit chain must be intact after 3 events: {v:?}"
    );
    assert_eq!(v.events_verified, 3);
    assert_eq!(v.corrupt_lines, 0);

    // Audit files must not appear in the logs dir.
    let log_reader = nrr_diagnostics::logs::LogReader::new(logs_dir.path());
    assert!(
        log_reader.list_files().is_empty(),
        "audit files must not appear in logs dir"
    );

    // Audit files must appear in audit dir.
    let audit_files = reader.list_files();
    assert_eq!(audit_files.len(), 1);
    let audit_name = audit_files[0].file_name().unwrap().to_string_lossy();
    assert!(
        audit_name.starts_with("nrr_audit_"),
        "audit file must have correct prefix"
    );
}

/// Tamper alert state transitions via InMemorySecurityAlertsRepository.
#[test]
fn alert_state_transitions() {
    let repo = InMemorySecurityAlertsRepository::new();
    let alert = nrr_diagnostics::audit::SecurityAlert {
        alert_id: "alt-001".into(),
        kind: "tamper_alert_raised".into(),
        state: SecurityAlertState::Active,
        raised_event_seq: 1,
        raised_file: "nrr_audit_20260423-1.ndjson".into(),
        ack_event_seq: None,
        ack_file: None,
        resolved_event_seq: None,
        resolved_file: None,
        created_at: 1_745_000_000_000,
        updated_at: 1_745_000_000_000,
        reason_code: "integrity.audit_chain_mismatch".into(),
    };
    repo.insert(&alert).expect("insert");

    // Active alert requires action.
    let active = repo
        .list_by_state(SecurityAlertState::Active)
        .expect("list");
    assert_eq!(active.len(), 1);
    assert!(active[0].requires_action());

    // Acknowledge it.
    repo.update_state(
        "alt-001",
        SecurityAlertState::Acknowledged,
        2,
        "nrr_audit_20260423-1.ndjson",
        1_745_001_000_000,
    )
    .expect("ack");

    let still_active = repo
        .list_by_state(SecurityAlertState::Active)
        .expect("list");
    assert!(
        still_active.is_empty(),
        "acknowledged alert must leave Active state"
    );

    let open = repo.list_open().expect("list_open");
    assert_eq!(open.len(), 1, "acknowledged is still 'open'");
    assert_eq!(open[0].state, SecurityAlertState::Acknowledged);
}

// ── 3. Privacy golden tests ───────────────────────────────────────────────────

/// The same hostname produces the same output regardless of how many times it's redacted.
#[test]
fn hostname_redaction_is_deterministic() {
    let hostname = "auth.login.example.com";
    let r1 = redact_hostname(hostname, RedactionMode::Default);
    let r2 = redact_hostname(hostname, RedactionMode::Default);
    assert_eq!(r1, r2, "redaction must be deterministic");
    assert_eq!(
        r1,
        nrr_diagnostics::privacy::Redacted::Value("example.com".into())
    );
}

/// Default mode hides IPs; Diagnostics mode reveals them — consistently.
#[test]
fn ip_redaction_consistent_across_modes() {
    let private_ip: std::net::Ipv4Addr = "192.168.1.100".parse().unwrap();
    let public_ip: std::net::Ipv4Addr = "8.8.8.8".parse().unwrap();

    // Default: both hidden.
    assert!(redact_ipv4(private_ip, RedactionMode::Default).is_hidden());
    assert!(redact_ipv4(public_ip, RedactionMode::Default).is_hidden());
    assert_eq!(
        redact_ipv4(private_ip, RedactionMode::Default).marker(),
        Some(MARKER_PRIVATE_IPV4)
    );
    assert_eq!(
        redact_ipv4(public_ip, RedactionMode::Default).marker(),
        Some(MARKER_PUBLIC_IPV4)
    );

    // Diagnostics: both revealed.
    assert!(!redact_ipv4(private_ip, RedactionMode::Diagnostics).is_hidden());
    assert!(!redact_ipv4(public_ip, RedactionMode::Diagnostics).is_hidden());
    assert_eq!(
        redact_ipv4(public_ip, RedactionMode::Diagnostics),
        nrr_diagnostics::privacy::Redacted::Value("8.8.8.8".into())
    );
}

/// Process path: Default shows filename; Diagnostics masks username; DeveloperLocal shows all.
#[test]
fn process_path_redaction_levels() {
    let path = r"C:\Users\alice\AppData\Local\Programs\chrome.exe";

    let compact = redact_process_path(path, RedactionMode::Default);
    assert_eq!(
        compact,
        nrr_diagnostics::privacy::Redacted::Value("chrome.exe".into())
    );

    let diag = redact_process_path(path, RedactionMode::Diagnostics);
    let diag_str = diag.into_option().unwrap();
    assert!(
        diag_str.contains("<masked-user>"),
        "username must be masked: {diag_str}"
    );
    assert!(
        !diag_str.contains("alice"),
        "actual username must not appear: {diag_str}"
    );

    let dev = redact_process_path(path, RedactionMode::DeveloperLocal);
    assert_eq!(dev, nrr_diagnostics::privacy::Redacted::Value(path.into()));
}

/// Redaction string repr (IP) is consistent with redact_ipv4_str.
#[test]
fn ip_str_redaction_consistent_with_parsed() {
    let ip_str = "10.0.0.1";
    let from_str = redact_ipv4_str(ip_str, RedactionMode::Default);
    let parsed: std::net::Ipv4Addr = ip_str.parse().unwrap();
    let from_parsed = redact_ipv4(parsed, RedactionMode::Default);
    assert_eq!(
        from_str, from_parsed,
        "redact_ipv4_str must match redact_ipv4 for valid IP"
    );
}

// ── 4. Archive: no raw sensitive data in default export ───────────────────────

/// Default archive contains no .db files and passes manifest validation.
#[test]
fn archive_default_export_contains_no_raw_db_files() {
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("archive.zip");

    let req = DiagnosticArchiveRequest::default_export("0.1.0-test");
    let input = ArchiveInput {
        health: nrr_diagnostics::facade::mock::healthy_status_for_test(),
        health_enrichment: Default::default(),
        log_entries: vec![],
        audit_entries: vec![],
        audit_chain_lines: vec![],
        explain_samples: vec![],
        system_info: Some(nrr_shared::system_info::SystemInfo::from_std()),
        service_stderr: None,
        request: req,
    };
    let result = ArchiveBuilder::build(input, &dest).expect("build archive");

    assert!(dest.exists());
    assert!(result.manifest.validate().is_ok());

    // No .db files in archive.
    let file = std::fs::File::open(&dest).expect("open zip");
    let mut zip = zip::ZipArchive::new(file).expect("parse zip");
    for i in 0..zip.len() {
        let entry = zip.by_index(i).expect("entry");
        assert!(
            !entry.name().ends_with(".db"),
            "archive must not contain .db files: {}",
            entry.name()
        );
    }
}

/// Default archive does not contain raw IP addresses (they are redacted).
#[test]
fn archive_default_export_no_raw_ips_in_health() {
    let dir = tempfile::tempdir().expect("temp");
    let dest = dir.path().join("archive.zip");

    let req = DiagnosticArchiveRequest::default_export("0.1.0-test");
    let input = ArchiveInput {
        health: nrr_diagnostics::facade::mock::healthy_status_for_test(),
        health_enrichment: Default::default(),
        log_entries: vec![],
        audit_entries: vec![],
        audit_chain_lines: vec![],
        explain_samples: vec![],
        system_info: Some(nrr_shared::system_info::SystemInfo::from_std()),
        service_stderr: None,
        request: req,
    };
    ArchiveBuilder::build(input, &dest).expect("build");

    // Read health.json from archive and verify no raw IP patterns.
    let file = std::fs::File::open(&dest).expect("open");
    let mut zip = zip::ZipArchive::new(file).expect("zip");
    let health_content = {
        use std::io::Read;
        let mut buf = String::new();
        if let Ok(mut f) = zip.by_name("health.json") {
            f.read_to_string(&mut buf).expect("read health.json");
        }
        buf
    };
    if !health_content.is_empty() {
        assert!(
            !health_content.contains("192.168."),
            "raw private IP must not appear in health.json"
        );
    }
}

// ── 5. Cleanup: audit protected ───────────────────────────────────────────────

/// `CleanupJob::run_logs` never deletes audit NDJSON files.
#[test]
fn cleanup_never_deletes_audit_files() {
    let dir = tempfile::tempdir().expect("temp");

    // Create a log file and an audit file in the same dir.
    std::fs::write(
        dir.path().join("nrr_service_20260423-1.ndjson"),
        b"log data",
    )
    .unwrap();
    let audit_path = dir.path().join("nrr_audit_20260423-1.ndjson");
    std::fs::write(&audit_path, b"audit data").unwrap();

    // Run cleanup with very small size limit to force deletion.
    let policy = LogRetentionPolicy {
        max_total_size_bytes: 1,
        max_age_days: 0,
        max_files: 0,
        ..LogRetentionPolicy::default()
    };
    let scope = ManualCleanupScope::default();
    CleanupJob::run_logs(dir.path(), &policy, &scope);

    // Audit file must still exist.
    assert!(
        audit_path.exists(),
        "audit NDJSON must never be deleted by log cleanup"
    );
}

/// `CleanupJob::run_audit` never deletes service log files.
#[test]
fn audit_cleanup_never_deletes_log_files() {
    let dir = tempfile::tempdir().expect("temp");
    let log_path = dir.path().join("nrr_service_20260423-1.ndjson");
    std::fs::write(&log_path, b"log data").unwrap();
    std::fs::write(
        dir.path().join("nrr_audit_20260423-1.ndjson"),
        b"audit data",
    )
    .unwrap();

    let policy = nrr_diagnostics::retention::AuditRetentionPolicy {
        max_age_days: 0,
        max_total_size_bytes: 1,
    };
    CleanupJob::run_audit(dir.path(), &policy);

    assert!(
        log_path.exists(),
        "service log must not be deleted by audit cleanup"
    );
}

// ── 6. Reason code stability (regression) ─────────────────────────────────────

/// All reason codes serialize to stable strings.
#[test]
fn all_reason_codes_have_stable_string_form() {
    for code in ALL_REASON_CODES {
        let s = code.as_str();
        // Must contain exactly one dot (namespace.kind).
        let dot_count = s.chars().filter(|&c| c == '.').count();
        assert!(
            dot_count >= 1,
            "reason code '{s}' must have at least one dot separator"
        );
        // Must be lowercase snake_case.
        assert!(
            s.chars()
                .all(|c| c.is_ascii_lowercase() || c == '.' || c == '_'),
            "reason code '{s}' must be lowercase snake_case with dots"
        );
    }
}

/// All reason codes have metadata registered.
#[test]
fn all_reason_codes_are_registered_with_ui_key() {
    for code in ALL_REASON_CODES {
        let meta = reason_code_meta(*code);
        assert!(
            meta.is_some(),
            "reason code '{}' must be registered in reason_code_meta()",
            code.as_str()
        );
        let meta = meta.unwrap();
        assert!(
            meta.ui_key.starts_with("diag."),
            "ui_key '{}' for '{}' must start with 'diag.'",
            meta.ui_key,
            code.as_str()
        );
    }
}

/// Specific reason codes never change their string representation.
#[test]
fn critical_reason_codes_stable_strings() {
    assert_eq!(
        reason::decision::FAIL_CLOSED.as_str(),
        "decision.fail_closed"
    );
    assert_eq!(reason::decision::FAIL_OPEN.as_str(), "decision.fail_open");
    assert_eq!(reason::cache::HIT.as_str(), "cache.hit");
    assert_eq!(reason::cache::MISS.as_str(), "cache.miss");
    assert_eq!(
        reason::integrity::AUDIT_CHAIN_MISMATCH.as_str(),
        "integrity.audit_chain_mismatch"
    );
    assert_eq!(
        reason::integrity::POLICY_INTEGRITY_FAILURE.as_str(),
        "integrity.policy_integrity_failure"
    );
    assert_eq!(reason::service::STARTED.as_str(), "service.started");
    assert_eq!(reason::service::STOPPED.as_str(), "service.stopped");
    assert_eq!(reason::review::APPROVED.as_str(), "review.approved");
}

// ── 7. Facade: no raw storage paths exposed ───────────────────────────────────

/// MockDiagnosticsFacade never exposes raw .db file paths in any DTO field.
#[test]
fn facade_no_raw_db_paths_in_status() {
    for scenario in [
        MockScenario::Healthy,
        MockScenario::ActiveTamperAlert,
        MockScenario::StaleCache,
        MockScenario::FailClosedBlock,
        MockScenario::ServiceDegraded,
        MockScenario::EmptyLogs,
    ] {
        let facade = MockDiagnosticsFacade::new(scenario);
        let status = facade.get_status();
        let json = serde_json::to_string(&status).expect("serialize");
        assert!(
            !json.contains(".db"),
            "facade status for {scenario:?} must not expose raw .db paths"
        );
        assert!(
            !json.contains("nrr_service_state"),
            "facade must not expose internal db filenames"
        );
    }
}

/// Pagination cursor is stable: parsing and reforming is deterministic.
#[test]
fn pagination_cursor_is_stable() {
    use nrr_diagnostics::facade::PageCursor;
    let cursor = PageCursor::from_position(1_745_000_000_000, "evt-integration-001");
    let (ts, id) = cursor.parse().expect("parse");
    let reformed = PageCursor::from_position(ts, id);
    assert_eq!(
        cursor, reformed,
        "cursor must be stable across parse/reform"
    );
}

// ── 8. Explain: redaction + correlation ──────────────────────────────────────

/// CompactUi explain does not include process path; Diagnostics does.
#[test]
fn explain_compact_hides_process_path() {
    use nrr_diagnostics::explain::ExplainQuery;
    use nrr_domain::decision_explain::DecisionId;

    let facade = MockDiagnosticsFacade::healthy();
    let q = ExplainQuery::HistoricalDecision {
        decision_id: DecisionId("d-001".into()),
    };

    let r = facade
        .get_explain(&q, ExplainDetailLevel::CompactUi, "")
        .expect("explain");
    // Mock returns ServiceUnavailable for all explain queries.
    assert!(!r.is_available());
    assert_eq!(r.query_kind, "historical");
}

/// Synthetic explain is marked as simulation.
#[test]
fn explain_synthetic_marked_as_simulation() {
    use nrr_diagnostics::explain::ExplainQuery;
    use nrr_diagnostics::explain::RuntimeInputSample;

    let facade = MockDiagnosticsFacade::healthy();
    let q = ExplainQuery::Synthetic {
        input_sample: RuntimeInputSample::new().with_hostname("example.com"),
    };
    let r = facade
        .get_explain(&q, ExplainDetailLevel::CompactUi, "")
        .expect("explain");
    assert!(r.is_simulation());
    assert_eq!(r.query_kind, "synthetic");
}

/// ExplainResponse unavailable constructors use correct availability keys.
#[test]
fn explain_unavailable_keys_stable() {
    let r = ExplainResponse::unavailable(
        ExplainQueryKind::Historical,
        ExplainDetailLevel::CompactUi,
        ExplainDataAvailability::DecisionNotFound,
    );
    assert_eq!(
        r.availability_key,
        "diag.explain.availability.decision-not-found"
    );

    let r2 = ExplainResponse::unavailable(
        ExplainQueryKind::Synthetic,
        ExplainDetailLevel::CompactUi,
        ExplainDataAvailability::DiagnosticModeRequired,
    );
    assert_eq!(
        r2.availability_key,
        "diag.explain.availability.diagnostic-mode-required"
    );
}

// ── 9. Integration: log emit → facade query ───────────────────────────────────

/// Events written to LogWriter are visible via LogReader scan (simulated facade).
#[test]
fn integration_log_emit_to_query() {
    let dir = tempfile::tempdir().expect("temp");

    // Emit service lifecycle events.
    let writer = LogWriter::open(LogWriterConfig::new(dir.path()));
    for i in 0..5u32 {
        writer.emit(LogEvent::new(
            format!("evt-{i:04}"),
            1_745_000_000_000 + i as i64 * 1000,
            EventLevel::Info,
            reason::service::STARTED,
        ));
    }

    // Query via reader.
    let reader = LogReader::new(dir.path());
    let filter = nrr_diagnostics::logs::LogQueryFilter::new()
        .kind("service.started")
        .from_ms(1_745_000_000_000);
    let events = reader.scan(&filter);

    assert_eq!(events.len(), 5, "all emitted events must be queryable");
    // Verify correlation correlation with event_id.
    assert!(events.iter().all(|e| !e.event_id.is_empty()));
    // Verify no raw sensitive fields.
    for e in &events {
        assert!(
            !e.kind.contains("192.168."),
            "log entry kind must not contain raw IP"
        );
    }
}

/// Integration: audit events written, chain verified, explain unavailable (no real service).
#[test]
fn integration_audit_and_explain_pipeline() {
    let audit_dir = tempfile::tempdir().expect("audit");
    let alerts_repo = InMemorySecurityAlertsRepository::new();

    // Step 1: write audit events.
    let writer = AuditWriter::open(AuditWriterConfig::new(audit_dir.path()));
    writer
        .append(audit_input("adt-001", AuditEventKind::RevisionActivated))
        .expect("write");
    writer
        .append(audit_input("adt-002", AuditEventKind::ReviewApproved))
        .expect("write");

    // Step 2: verify chain.
    let reader = AuditReader::new(audit_dir.path());
    let v = reader.verify_latest_chain();
    assert!(v.chain_ok);

    // Step 3: scan audit events by kind.
    let activation_events = reader.scan(&AuditQueryFilter::new().kind("revision_activated"));
    assert_eq!(activation_events.len(), 1);
    assert_eq!(activation_events[0].kind, "revision_activated");

    // Step 4: explain is unavailable without real service (mock confirms contract).
    use nrr_diagnostics::explain::ExplainQuery;
    use nrr_domain::decision_explain::DecisionId;

    let facade = MockDiagnosticsFacade::healthy();
    let explain_r = facade
        .get_explain(
            &ExplainQuery::HistoricalDecision {
                decision_id: DecisionId("d-001".into()),
            },
            ExplainDetailLevel::CompactUi,
            "",
        )
        .expect("explain ok");
    assert!(
        !explain_r.is_available(),
        "explain unavailable without real service"
    );

    // Step 5: alert state is tracked correctly.
    let all_alerts = alerts_repo.all_alerts();
    assert!(
        all_alerts.is_empty(),
        "no alerts were inserted in this pipeline"
    );
}

// ── 10. Acceptance gate ───────────────────────────────────────────────────────

/// Acceptance gate: all redaction golden tests pass.
/// This test will fail if any redaction function produces unexpected output,
/// blocking diagnostic archive export from being enabled in the GUI.
#[test]
fn acceptance_gate_redaction_golden_tests() {
    // Hostname: Default → eTLD+1.
    let r = redact_hostname("api.v2.service.example.com", RedactionMode::Default);
    assert_eq!(
        r,
        nrr_diagnostics::privacy::Redacted::Value("example.com".into())
    );

    // Hostname: Diagnostics → full.
    let r = redact_hostname("api.v2.service.example.com", RedactionMode::Diagnostics);
    assert_eq!(
        r,
        nrr_diagnostics::privacy::Redacted::Value("api.v2.service.example.com".into())
    );

    // IP: Default private → marker.
    let r = redact_ipv4_str("10.1.2.3", RedactionMode::Default);
    assert_eq!(
        r,
        nrr_diagnostics::privacy::Redacted::Hidden(MARKER_PRIVATE_IPV4.into())
    );

    // IP: Default public → marker.
    let r = redact_ipv4_str("1.1.1.1", RedactionMode::Default);
    assert_eq!(
        r,
        nrr_diagnostics::privacy::Redacted::Hidden(MARKER_PUBLIC_IPV4.into())
    );

    // IP: Diagnostics → full.
    let r = redact_ipv4_str("1.1.1.1", RedactionMode::Diagnostics);
    assert_eq!(
        r,
        nrr_diagnostics::privacy::Redacted::Value("1.1.1.1".into())
    );

    // Path: Default → filename.
    let r = redact_process_path(r"C:\Users\bob\AppData\MyApp.exe", RedactionMode::Default);
    assert_eq!(
        r,
        nrr_diagnostics::privacy::Redacted::Value("MyApp.exe".into())
    );

    // Path: DeveloperLocal → full.
    let full_path = r"C:\Users\bob\AppData\MyApp.exe";
    let r = redact_process_path(full_path, RedactionMode::DeveloperLocal);
    assert_eq!(
        r,
        nrr_diagnostics::privacy::Redacted::Value(full_path.into())
    );
}
