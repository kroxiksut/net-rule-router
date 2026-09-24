use super::*;
use nrr_diagnostics::audit::alert::InMemorySecurityAlertsRepository;
use nrr_diagnostics::audit::writer::{AuditEventInput, AuditWriter, AuditWriterConfig};
use nrr_diagnostics::audit::{ActorKind, AuditEventKind, AuditEventResult};
use nrr_diagnostics::reason::ReasonCode;
use nrr_diagnostics::sink::AuditSink;
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;

/// The engine takes the Zone-vs-ExactIp order as a parameter and both
/// production callers passed the default, so the setting the rule model
/// documents could not take effect. It is now stored per principal and read
/// here.
#[test]
fn the_zone_priority_setting_reaches_the_matcher() {
    use nrr_storage::migration::{open_connection, SqliteMigrationRunner};
    use nrr_storage::repository::MigrationRunner;

    let dir = TempDir::new().expect("tmp");
    let conn = open_connection(&dir.path().join("state.db")).expect("open");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("migrate");
    let conn = Arc::new(std::sync::Mutex::new(runner.into_connection()));
    let alerts: Arc<dyn SecurityAlertsRepository> =
        Arc::new(InMemorySecurityAlertsRepository::new());
    let facade = ProductionDiagnosticsFacade::new(
        dir.path(),
        dir.path(),
        None,
        alerts,
        Some(Arc::clone(&conn)),
    );
    let sid = "S-1-5-21-zone";

    // Nothing stored yet: the documented default (the exact address wins).
    assert!(facade.zone_policy_for_sid(sid).prefer_ip);

    {
        let guard = conn.lock().expect("lock");
        let repo = nrr_storage::route_bindings::RouteBindingsRepository::new(&guard);
        let mut policy = repo.load_for_sid(sid).expect("load policy");
        policy.zone_priority_over_ip = true;
        repo.update_for_sid(sid, &policy, 0).expect("store policy");
        assert!(
            repo.load_for_sid(sid)
                .expect("reload")
                .zone_priority_over_ip,
            "storage round-trip"
        );
    }
    assert!(
        !facade.zone_policy_for_sid(sid).prefer_ip,
        "the stored setting must reach the matcher"
    );
}

fn make_facade(audit_dir: &Path, logs_dir: &Path) -> ProductionDiagnosticsFacade {
    let alerts: Arc<dyn SecurityAlertsRepository> =
        Arc::new(InMemorySecurityAlertsRepository::new());
    ProductionDiagnosticsFacade::new(logs_dir, audit_dir, None, alerts, None)
}

fn write_audit_event(dir: &Path, suffix: &str) {
    let writer = AuditWriter::open(AuditWriterConfig::new(dir));
    writer
        .append(AuditEventInput {
            event_id: format!("adt-{suffix}"),
            kind: AuditEventKind::RevisionActivated,
            created_at: 1_700_000_000_000,
            actor_kind: ActorKind::Service,
            actor_id_hash: None,
            revision_id: Some("rev-1".to_string()),
            risk_level: None,
            result: AuditEventResult::Success,
            reason_code: ReasonCode("apply.completed"),
            payload_summary_json: Some(r#"{"event":"test"}"#.to_string()),
        })
        .expect("audit append");
}

/// An event performed BY a user, hashed the same way the production writer
/// hashes it.
fn write_user_audit_event(dir: &Path, suffix: &str, principal: &str) {
    let writer = AuditWriter::open(AuditWriterConfig::new(dir));
    writer
        .append(AuditEventInput {
            event_id: format!("adt-{suffix}"),
            kind: AuditEventKind::RevisionActivated,
            created_at: 1_700_000_000_000,
            actor_kind: ActorKind::User,
            actor_id_hash: nrr_diagnostics::audit::actor_id_hash(principal),
            revision_id: Some("rev-1".to_string()),
            risk_level: None,
            result: AuditEventResult::Success,
            reason_code: ReasonCode("apply.completed"),
            payload_summary_json: Some(r#"{"event":"test"}"#.to_string()),
        })
        .expect("audit append");
}

#[test]
fn get_status_reports_individual_cards_with_no_storage_attached() {
    // Degraded boot: cache_conn = None and state_conn = None
    // mimic the recovery path where storage isn't open yet.
    // `cache_health.healthy = false` is the documented response
    // for that case (see `compute_cache_health`), which in turn
    // forces `overall_healthy = false`. The test pins the
    // individual cards rather than the aggregate.
    let dir = TempDir::new().expect("tempdir");
    let audit_dir = dir.path().join("audit");
    let logs_dir = dir.path().join("logs");
    std::fs::create_dir_all(&audit_dir).unwrap();
    std::fs::create_dir_all(&logs_dir).unwrap();
    let facade = make_facade(&audit_dir, &logs_dir);
    let status = facade.get_status();
    assert!(status.security_status.audit_chain_ok);
    assert!(status.security_status.audit_write_healthy);
    assert!(status.log_health.dir_writable);
    assert_eq!(status.security_status.active_alert_count, 0);
    assert_eq!(status.service_health.state, "running");
    assert!(!status.diagnostic_mode.active);
    // With no cache connection, the card reports unhealthy.
    assert!(!status.cache_health.healthy);
    assert_eq!(status.cache_health.entry_count, 0);
    // Aggregate flips to false because of the cache_health gate.
    assert!(!status.overall_healthy);
}

/// One user must not read another user's audit entries. The trail is a
/// machine-wide file the filesystem keeps closed to ordinary users, so an
/// unscoped IPC read would hand out what those permissions withhold.
#[test]
fn a_principal_scoped_read_sees_its_own_events_and_the_services_own() {
    let dir = TempDir::new().expect("tempdir");
    let audit_dir = dir.path().join("audit");
    let logs_dir = dir.path().join("logs");
    std::fs::create_dir_all(&audit_dir).unwrap();
    std::fs::create_dir_all(&logs_dir).unwrap();

    let mine = "S-1-5-21-mine";
    let theirs = "S-1-5-21-theirs";
    write_user_audit_event(&audit_dir, "001", mine);
    write_user_audit_event(&audit_dir, "002", theirs);
    // The service acting on its own behalf: a fact about the machine.
    write_audit_event(&audit_dir, "003");

    let facade = make_facade(&audit_dir, &logs_dir);
    let page = PaginationParams {
        cursor: None,
        page_size: 50,
    };
    let scoped = facade
        .list_audit_entries(
            &AuditEntryFilter::default(),
            &page,
            &DiagnosticsAudience::Principal(mine.to_string()),
        )
        .expect("scoped read");
    let ids: Vec<&str> = scoped.items.iter().map(|e| e.event_id.as_str()).collect();
    assert!(
        ids.contains(&"adt-001"),
        "own event must be visible: {ids:?}"
    );
    assert!(
        ids.contains(&"adt-003"),
        "service event must be visible: {ids:?}"
    );
    assert!(
        !ids.contains(&"adt-002"),
        "another principal's event must not be visible: {ids:?}"
    );

    // An administrator sees the whole trail — that is what elevation buys.
    let all = facade
        .list_audit_entries(
            &AuditEntryFilter::default(),
            &page,
            &DiagnosticsAudience::Machine,
        )
        .expect("machine-wide read");
    assert_eq!(all.items.len(), 3);
}

#[test]
fn list_audit_entries_pages_and_emits_cursor() {
    let dir = TempDir::new().expect("tempdir");
    let audit_dir = dir.path().join("audit");
    let logs_dir = dir.path().join("logs");
    std::fs::create_dir_all(&audit_dir).unwrap();
    std::fs::create_dir_all(&logs_dir).unwrap();
    // Write 5 audit events.
    for i in 0..5 {
        write_audit_event(&audit_dir, &format!("{i:03}"));
    }
    let facade = make_facade(&audit_dir, &logs_dir);
    let filter = AuditEntryFilter::default();
    let p1 = PaginationParams {
        cursor: None,
        page_size: 2,
    };
    let page1 = facade
        .list_audit_entries(&filter, &p1, &DiagnosticsAudience::Machine)
        .unwrap();
    assert_eq!(page1.items.len(), 2);
    assert!(page1.next_cursor.is_some());
    assert_eq!(page1.total_count, Some(5));
    assert!(
        page1.items[0].created_at >= page1.items[1].created_at,
        "audit pages newest-first"
    );

    let p2 = PaginationParams {
        cursor: page1.next_cursor.clone(),
        page_size: 2,
    };
    let page2 = facade
        .list_audit_entries(&filter, &p2, &DiagnosticsAudience::Machine)
        .unwrap();
    assert_eq!(page2.items.len(), 2);
    assert!(page2.next_cursor.is_some());

    let p3 = PaginationParams {
        cursor: page2.next_cursor.clone(),
        page_size: 2,
    };
    let page3 = facade
        .list_audit_entries(&filter, &p3, &DiagnosticsAudience::Machine)
        .unwrap();
    assert_eq!(page3.items.len(), 1);
    assert!(
        page3.next_cursor.is_none(),
        "last page must terminate cursor"
    );
}

/// The Logs view opens on the first page, so that page is the latest activity
/// and "load more" walks back in time.
#[test]
fn list_log_entries_pages_newest_first_without_gaps() {
    let dir = TempDir::new().expect("tempdir");
    let audit_dir = dir.path().join("audit");
    let logs_dir = dir.path().join("logs");
    std::fs::create_dir_all(&audit_dir).unwrap();
    std::fs::create_dir_all(&logs_dir).unwrap();
    write_log_events(&logs_dir, 7);
    let facade = make_facade(&audit_dir, &logs_dir);

    let mut ids = Vec::new();
    let mut cursor = None;
    for _ in 0..10 {
        let page = facade
            .list_log_entries(
                &LogEntryFilter::default(),
                &PaginationParams {
                    cursor: cursor.clone(),
                    page_size: 3,
                },
                &DiagnosticsAudience::Machine,
            )
            .unwrap();
        ids.extend(page.items.into_iter().map(|e| e.event_id));
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    let expected: Vec<String> = (1..=7).rev().map(|i| format!("evt-{i:04}")).collect();
    assert_eq!(ids, expected);
}

#[test]
fn list_log_entries_returns_empty_on_no_files() {
    let dir = TempDir::new().expect("tempdir");
    let audit_dir = dir.path().join("audit");
    let logs_dir = dir.path().join("logs");
    std::fs::create_dir_all(&audit_dir).unwrap();
    std::fs::create_dir_all(&logs_dir).unwrap();
    let facade = make_facade(&audit_dir, &logs_dir);
    let r = facade
        .list_log_entries(
            &LogEntryFilter::default(),
            &PaginationParams::default(),
            &DiagnosticsAudience::Machine,
        )
        .unwrap();
    assert!(r.items.is_empty());
    assert!(r.next_cursor.is_none());
}

/// Writes `n` operational log events `evt-0001..evt-000n` with strictly
/// increasing `created_at` directly to an NDJSON rotation file (bypasses
/// the writer allowlist, like the reader's own tests).
fn write_log_events(dir: &Path, n: u32) {
    use nrr_diagnostics::event::LogEvent;
    use nrr_diagnostics::reason::service::STARTED;
    use nrr_diagnostics::taxonomy::EventLevel;
    use std::io::Write;
    let date = nrr_diagnostics::audit::writer::local_date_string(std::time::SystemTime::now());
    let path = dir.join(format!("nrr_service_{date}-1.ndjson"));
    let mut file = std::fs::File::create(&path).expect("create log file");
    for i in 1..=n {
        let event = LogEvent::new(
            format!("evt-{i:04}"),
            1_745_000_000_000 + i as i64 * 1000,
            EventLevel::Info,
            STARTED,
        );
        writeln!(file, "{}", event.to_ndjson().expect("serialize")).expect("write");
    }
}

/// The operational log is one machine-wide stream, so a line about one
/// user's routing must not reach another user's Logs view. Machine-level
/// lines — the ones that belong to nobody — stay visible to everyone,
/// because without them the view stops being a timeline.
#[test]
fn a_principal_scoped_log_read_keeps_machine_lines_and_drops_other_users() {
    use nrr_diagnostics::event::LogEvent;
    use nrr_diagnostics::reason::service::STARTED;
    use nrr_diagnostics::taxonomy::EventLevel;
    use std::io::Write;

    let dir = TempDir::new().expect("tempdir");
    let audit_dir = dir.path().join("audit");
    let logs_dir = dir.path().join("logs");
    std::fs::create_dir_all(&audit_dir).unwrap();
    std::fs::create_dir_all(&logs_dir).unwrap();

    let date = nrr_diagnostics::audit::writer::local_date_string(std::time::SystemTime::now());
    let path = logs_dir.join(format!("nrr_service_{date}-1.ndjson"));
    let mut file = std::fs::File::create(&path).expect("create log file");
    let owners = [None, Some("S-1-5-21-mine"), Some("S-1-5-21-theirs")];
    for (i, owner) in owners.iter().enumerate() {
        let mut event = LogEvent::new(
            format!("evt-{i:04}"),
            1_745_000_000_000 + i as i64 * 1000,
            EventLevel::Info,
            STARTED,
        );
        event.principal = owner.map(str::to_owned);
        writeln!(file, "{}", event.to_ndjson().expect("serialize")).expect("write");
    }
    drop(file);

    let facade = make_facade(&audit_dir, &logs_dir);
    let page = PaginationParams {
        cursor: None,
        page_size: 50,
    };
    let scoped = facade
        .list_log_entries(
            &LogEntryFilter::default(),
            &page,
            &DiagnosticsAudience::Principal("S-1-5-21-mine".to_string()),
        )
        .expect("scoped read");
    let ids: Vec<&str> = scoped.items.iter().map(|e| e.event_id.as_str()).collect();
    assert!(ids.contains(&"evt-0000"), "machine line missing: {ids:?}");
    assert!(ids.contains(&"evt-0001"), "own line missing: {ids:?}");
    assert!(
        !ids.contains(&"evt-0002"),
        "another user's line must not be visible: {ids:?}"
    );

    let all = facade
        .list_log_entries(
            &LogEntryFilter::default(),
            &page,
            &DiagnosticsAudience::Machine,
        )
        .expect("machine-wide read");
    assert_eq!(all.items.len(), 3);
}

#[test]
fn recent_log_entries_returns_newest_first() {
    let dir = TempDir::new().expect("tempdir");
    let audit_dir = dir.path().join("audit");
    let logs_dir = dir.path().join("logs");
    std::fs::create_dir_all(&audit_dir).unwrap();
    std::fs::create_dir_all(&logs_dir).unwrap();
    write_log_events(&logs_dir, 5);
    let facade = make_facade(&audit_dir, &logs_dir);
    let recent = facade
        .recent_log_entries(
            &LogEntryFilter::default(),
            100,
            &DiagnosticsAudience::Machine,
        )
        .expect("recent");
    let ids: Vec<&str> = recent.iter().map(|e| e.event_id.as_str()).collect();
    // Newest (highest created_at) first, i.e. the reverse of the ascending
    // scan — this is what the archive builder's byte budget trims from.
    assert_eq!(
        ids,
        vec!["evt-0005", "evt-0004", "evt-0003", "evt-0002", "evt-0001"]
    );
}

#[test]
fn recent_log_entries_caps_to_the_newest_max_entries() {
    let dir = TempDir::new().expect("tempdir");
    let audit_dir = dir.path().join("audit");
    let logs_dir = dir.path().join("logs");
    std::fs::create_dir_all(&audit_dir).unwrap();
    std::fs::create_dir_all(&logs_dir).unwrap();
    write_log_events(&logs_dir, 10);
    let facade = make_facade(&audit_dir, &logs_dir);
    let recent = facade
        .recent_log_entries(&LogEntryFilter::default(), 3, &DiagnosticsAudience::Machine)
        .expect("recent");
    let ids: Vec<&str> = recent.iter().map(|e| e.event_id.as_str()).collect();
    // Only the 3 NEWEST, newest-first — never the stale head a
    // single-oldest-page fetch would ship.
    assert_eq!(ids, vec!["evt-0010", "evt-0009", "evt-0008"]);
}

#[test]
fn recent_log_entries_zero_cap_is_empty() {
    let dir = TempDir::new().expect("tempdir");
    let audit_dir = dir.path().join("audit");
    let logs_dir = dir.path().join("logs");
    std::fs::create_dir_all(&audit_dir).unwrap();
    std::fs::create_dir_all(&logs_dir).unwrap();
    write_log_events(&logs_dir, 3);
    let facade = make_facade(&audit_dir, &logs_dir);
    assert!(facade
        .recent_log_entries(&LogEntryFilter::default(), 0, &DiagnosticsAudience::Machine)
        .expect("recent")
        .is_empty());
}

#[test]
fn list_active_alerts_proxies_repo() {
    let dir = TempDir::new().expect("tempdir");
    let audit_dir = dir.path().join("audit");
    let logs_dir = dir.path().join("logs");
    std::fs::create_dir_all(&audit_dir).unwrap();
    std::fs::create_dir_all(&logs_dir).unwrap();
    let repo: Arc<dyn SecurityAlertsRepository> = Arc::new(InMemorySecurityAlertsRepository::new());
    let alert = SecurityAlert {
        alert_id: "alt-test".into(),
        kind: "tamper_alert_raised".into(),
        state: nrr_diagnostics::audit::alert::SecurityAlertState::Active,
        raised_event_seq: 1,
        raised_file: "nrr_audit_test.ndjson".into(),
        ack_event_seq: None,
        ack_file: None,
        resolved_event_seq: None,
        resolved_file: None,
        created_at: 1_700_000_000_000,
        updated_at: 1_700_000_000_000,
        reason_code: "integrity.audit_chain_mismatch".into(),
    };
    repo.insert(&alert).expect("insert");
    let facade = ProductionDiagnosticsFacade::new(&logs_dir, &audit_dir, None, repo, None);
    let alerts = facade.list_active_alerts().expect("list");
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].alert_id, "alt-test");
    assert!(alerts[0].requires_action);
}

#[test]
fn acknowledge_alert_rejects_empty_id() {
    let dir = TempDir::new().expect("tempdir");
    let audit_dir = dir.path().join("audit");
    let logs_dir = dir.path().join("logs");
    std::fs::create_dir_all(&audit_dir).unwrap();
    std::fs::create_dir_all(&logs_dir).unwrap();
    let facade = make_facade(&audit_dir, &logs_dir);
    let r = facade.acknowledge_alert(&AcknowledgeAlertRequest {
        alert_id: String::new(),
        reason: None,
    });
    assert!(r.is_err());
}

#[test]
fn acknowledge_alert_directs_caller_to_mutation_queue() {
    let dir = TempDir::new().expect("tempdir");
    let audit_dir = dir.path().join("audit");
    let logs_dir = dir.path().join("logs");
    std::fs::create_dir_all(&audit_dir).unwrap();
    std::fs::create_dir_all(&logs_dir).unwrap();
    let facade = make_facade(&audit_dir, &logs_dir);
    let r = facade.acknowledge_alert(&AcknowledgeAlertRequest {
        alert_id: "alt-x".into(),
        reason: None,
    });
    assert!(r.is_err(), "direct ack must be rejected");
}

#[test]
fn set_diagnostic_mode_enable_then_disable() {
    let dir = TempDir::new().expect("tempdir");
    let audit_dir = dir.path().join("audit");
    let logs_dir = dir.path().join("logs");
    std::fs::create_dir_all(&audit_dir).unwrap();
    std::fs::create_dir_all(&logs_dir).unwrap();
    let facade = make_facade(&audit_dir, &logs_dir);
    // Initial state inactive.
    assert!(!facade.get_status().diagnostic_mode.active);
    // Enable.
    facade
        .set_diagnostic_mode(&SetDiagnosticModeRequest {
            enabled: true,
            duration_ms: Some(60_000),
            scope: Some("decision_and_cache".into()),
            until_restart: false,
        })
        .unwrap();
    let status = facade.get_status();
    assert!(status.diagnostic_mode.active);
    assert!(status.diagnostic_mode.remaining_ms.unwrap_or(0) > 0);
    assert_eq!(
        status.diagnostic_mode.scope_key.as_deref(),
        Some("decision_and_cache")
    );
    // Disable.
    facade
        .set_diagnostic_mode(&SetDiagnosticModeRequest {
            enabled: false,
            duration_ms: None,
            scope: None,
            until_restart: false,
        })
        .unwrap();
    assert!(!facade.get_status().diagnostic_mode.active);
}

#[test]
fn clear_logs_dry_run_does_not_delete() {
    let dir = TempDir::new().expect("tempdir");
    let audit_dir = dir.path().join("audit");
    let logs_dir = dir.path().join("logs");
    std::fs::create_dir_all(&audit_dir).unwrap();
    std::fs::create_dir_all(&logs_dir).unwrap();
    // Write 3 placeholder log files.
    for i in 0..3 {
        std::fs::write(
            logs_dir.join(format!("nrr_service_20260101-{i}.ndjson")),
            format!("dummy line {i}\n"),
        )
        .unwrap();
    }
    let facade = make_facade(&audit_dir, &logs_dir);
    let r = facade
        .clear_logs(&ClearLogsRequest {
            include_archives: false,
            dry_run: true,
        })
        .unwrap();
    assert!(r.dry_run);
    assert_eq!(r.files_deleted, 3);
    assert!(r.bytes_freed > 0);
    // Files still on disk.
    let remaining = LogReader::new(&logs_dir).list_files();
    assert_eq!(remaining.len(), 3);
}

#[test]
fn clear_logs_real_deletes_files() {
    let dir = TempDir::new().expect("tempdir");
    let audit_dir = dir.path().join("audit");
    let logs_dir = dir.path().join("logs");
    std::fs::create_dir_all(&audit_dir).unwrap();
    std::fs::create_dir_all(&logs_dir).unwrap();
    for i in 0..2 {
        std::fs::write(
            logs_dir.join(format!("nrr_service_20260101-{i}.ndjson")),
            "dummy\n",
        )
        .unwrap();
    }
    let facade = make_facade(&audit_dir, &logs_dir);
    let r = facade
        .clear_logs(&ClearLogsRequest {
            include_archives: false,
            dry_run: false,
        })
        .unwrap();
    assert!(!r.dry_run);
    assert_eq!(r.files_deleted, 2);
    // Files gone.
    let remaining = LogReader::new(&logs_dir).list_files();
    assert!(remaining.is_empty());
}

#[test]
fn get_explain_historical_returns_decision_not_found() {
    let dir = TempDir::new().expect("tempdir");
    let audit_dir = dir.path().join("audit");
    let logs_dir = dir.path().join("logs");
    std::fs::create_dir_all(&audit_dir).unwrap();
    std::fs::create_dir_all(&logs_dir).unwrap();
    let facade = make_facade(&audit_dir, &logs_dir);
    let q = ExplainQuery::HistoricalDecision {
        decision_id: nrr_domain::decision_explain::DecisionId("d-unknown".into()),
    };
    let r = facade
        .get_explain(&q, ExplainDetailLevel::CompactUi, "")
        .unwrap();
    assert!(!r.is_available());
    assert_eq!(
        r.availability_key,
        ExplainDataAvailability::DecisionNotFound.ui_key()
    );
}

#[test]
fn get_explain_synthetic_with_no_rules_reports_default_primary() {
    // With no active revision (and no DB wired), the synthetic probe must
    // NOT report "service unavailable / save a rule first" — with no rules
    // every destination follows the DEFAULT route (primary). A user never
    // needs a saved rule for traffic to flow via the primary NIC.
    let dir = TempDir::new().expect("tempdir");
    let audit_dir = dir.path().join("audit");
    let logs_dir = dir.path().join("logs");
    std::fs::create_dir_all(&audit_dir).unwrap();
    std::fs::create_dir_all(&logs_dir).unwrap();
    let facade = make_facade(&audit_dir, &logs_dir);
    let q = ExplainQuery::Synthetic {
        input_sample: nrr_diagnostics::explain::RuntimeInputSample::new()
            .with_hostname("example.com"),
    };
    let r = facade
        .get_explain(&q, ExplainDetailLevel::Diagnostics, "")
        .unwrap();
    assert!(r.is_simulation(), "synthetic probe is always a simulation");
    assert!(
        r.is_available(),
        "no rules → default route, not unavailable"
    );
    assert_eq!(
        r.availability_key,
        ExplainDataAvailability::Available.ui_key()
    );
    let final_action = r
        .final_action_section
        .expect("default-route response has a final action");
    assert_eq!(
        final_action.route_role.as_deref(),
        Some("primary"),
        "unmatched destination with no rules must report the primary route"
    );
}

// An unmatched probe (DefaultRoute) must report the DEFAULT route, not
// "no route". This pins the projection that the synthetic explain uses.
#[test]
fn default_route_projection_maps_behavior_mode_to_route() {
    use nrr_domain::RouteBehaviorMode;
    assert_eq!(
        default_route_explain_projection(RouteBehaviorMode::PreferPrimary),
        ("primary", "diag.explain.final-action.route-primary"),
        "unmatched traffic under PreferPrimary must report the primary route, not none"
    );
    assert_eq!(
        default_route_explain_projection(RouteBehaviorMode::PreferSecondaryWhenAvailable),
        ("secondary", "diag.explain.final-action.route-secondary")
    );
    assert_eq!(
        default_route_explain_projection(RouteBehaviorMode::StrictSecondaryFailClosed),
        ("secondary", "diag.explain.final-action.route-secondary")
    );
}

#[test]
fn paginate_handles_empty_input() {
    let empty: Vec<LogEntryDto> = Vec::new();
    let r = paginate(empty, &PaginationParams::default(), log_entry_position);
    assert!(r.items.is_empty());
    assert!(r.next_cursor.is_none());
    assert_eq!(r.total_count, Some(0));
}

#[test]
fn diagnostic_session_handle_redaction_mode_inactive_returns_default() {
    let h = DiagnosticSessionHandle::new();
    assert_eq!(h.redaction_mode(0), RedactionMode::Default);
}

#[test]
fn diagnostic_session_handle_redaction_mode_active_returns_diagnostics() {
    let h = DiagnosticSessionHandle::new();
    let s = DiagnosticSession::new(
        1_000,
        60_000,
        "test-user",
        DiagnosticSessionScope::All,
        None,
    );
    h.store(Some(s));
    assert_eq!(h.redaction_mode(2_000), RedactionMode::Diagnostics);
}

fn log_entry(created_at: i64, event_id: &str) -> LogEntryDto {
    LogEntryDto {
        event_id: event_id.to_string(),
        created_at,
        level: "info".into(),
        category: "service".into(),
        kind: "service.started".into(),
        message_key: "diag.service.started.summary".into(),
        message: String::new(),
        has_payload: false,
        correlation_summary: Vec::new(),
        args: Default::default(),
    }
}

#[test]
fn paging_delivers_every_line_when_ids_are_unique() {
    // Same millisecond, distinct ids — exactly what the tracing layer now
    // produces, and what the cursor needs to page without losses.
    let items: Vec<LogEntryDto> = (0..5)
        .rev()
        .map(|n| log_entry(1_000, &format!("evt-{n}")))
        .collect();

    let mut delivered = 0usize;
    let mut cursor = None;
    for _ in 0..10 {
        let params = PaginationParams {
            cursor: cursor.clone(),
            page_size: 2,
        };
        let page = paginate(items.clone(), &params, log_entry_position);
        delivered += page.items.len();
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    assert_eq!(delivered, items.len());
}

#[test]
fn repeated_positions_are_reported_not_swallowed() {
    let items: Vec<LogEntryDto> = (0..3).map(|_| log_entry(1_000, "evt-same")).collect();
    assert_eq!(duplicate_positions(&items, log_entry_position), Some(2));

    let unique: Vec<LogEntryDto> = (0..3)
        .map(|n| log_entry(1_000, &format!("evt-{n}")))
        .collect();
    assert_eq!(duplicate_positions(&unique, log_entry_position), None);
}

#[test]
fn the_compact_explain_does_not_ship_the_full_hostname() {
    let dir = TempDir::new().expect("tempdir");
    let audit_dir = dir.path().join("audit");
    let logs_dir = dir.path().join("logs");
    std::fs::create_dir_all(&audit_dir).unwrap();
    std::fs::create_dir_all(&logs_dir).unwrap();
    let facade = make_facade(&audit_dir, &logs_dir);
    let q = ExplainQuery::Synthetic {
        input_sample: nrr_diagnostics::explain::RuntimeInputSample::new()
            .with_hostname("secret-project.internal.example.com"),
    };

    let compact = facade
        .get_explain(&q, ExplainDetailLevel::CompactUi, "")
        .unwrap();
    let hostname = compact
        .input
        .expect("input section")
        .destination_hostname
        .expect("hostname");
    assert_eq!(
        hostname, "example.com",
        "Compact must not carry the full hostname"
    );

    let detailed = facade
        .get_explain(&q, ExplainDetailLevel::Diagnostics, "")
        .unwrap();
    assert_eq!(
        detailed
            .input
            .expect("input section")
            .destination_hostname
            .as_deref(),
        Some("secret-project.internal.example.com"),
        "Diagnostics keeps the full hostname — that is what it is for"
    );
}

#[test]
fn a_tracing_events_text_reaches_the_log_view() {
    use nrr_diagnostics::event::LogEvent;
    use nrr_diagnostics::taxonomy::EventLevel;

    let mut event = LogEvent::new(
        "evt-1".to_string(),
        1_745_000_000_000,
        EventLevel::Info,
        nrr_diagnostics::reason::service::STARTED,
    );
    event.payload = Some(serde_json::json!({ "message": "kill-switch armed" }));

    let dto = log_event_to_dto(&event);
    assert_eq!(
        dto.message, "kill-switch armed",
        "the Logs section showed a category name because the text never left the NDJSON"
    );

    // An event with no message must not invent one.
    let mut bare = event.clone();
    bare.payload = None;
    assert!(log_event_to_dto(&bare).message.is_empty());
}

#[test]
fn a_tagged_events_key_and_scalar_fields_reach_the_log_view() {
    use nrr_diagnostics::event::LogEvent;
    use nrr_diagnostics::taxonomy::EventLevel;

    let mut event = LogEvent::new(
        "evt-2".to_string(),
        1_745_000_000_000,
        EventLevel::Info,
        nrr_diagnostics::reason::service::STARTED,
    );
    event.message_key = "diag.event.policy-applied".to_string();
    event.payload = Some(serde_json::json!({
        "message": "policy applied",
        "applied": 3,
        "guarded": true,
        "host": nrr_diagnostics::logs::privacy::REDACTED,
        "principals": ["S-1-5-21-7"],
    }));

    let dto = log_event_to_dto(&event);
    assert_eq!(dto.message_key, "diag.event.policy-applied");
    assert_eq!(dto.args.get("applied").map(String::as_str), Some("3"));
    assert_eq!(dto.args.get("guarded").map(String::as_str), Some("true"));
    assert_eq!(
        dto.args.get("host").map(String::as_str),
        Some(nrr_diagnostics::logs::privacy::REDACTED),
        "a redacted value stays redacted"
    );
    assert!(!dto.args.contains_key("message"));
    assert!(
        !dto.args.contains_key("principals"),
        "only scalars are placeholders"
    );

    // An untagged event keeps the convention key and carries no args.
    event.message_key = "tracing.nrr::service.service".to_string();
    event.payload = None;
    let dto = log_event_to_dto(&event);
    assert_eq!(
        dto.message_key,
        format!("diag.{}.{}.summary", event.category.as_str(), event.kind)
    );
    assert!(dto.args.is_empty());
}
