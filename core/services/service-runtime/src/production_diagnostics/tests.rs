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
    let status = facade.get_status(&DiagnosticsAudience::Machine);
    assert!(status.security_status.audit_chain_ok);
    assert!(status.security_status.audit_write_healthy);
    assert!(status.log_health.dir_writable);
    assert_eq!(status.security_status.active_alert_count, 0);
    assert_eq!(status.service_health.state, "running");
    // With no cache connection, the card reports unhealthy.
    assert!(!status.cache_health.healthy);
    assert_eq!(status.cache_health.entry_count, 0);
    // Aggregate flips to false because of the cache_health gate.
    assert!(!status.overall_healthy);
    assert!(status.security_status.alerts_readable);
}

/// An alert store that cannot be read must not look like one with nothing in
/// it: "No active alerts" is a claim the service did not make.
#[test]
fn an_unreadable_alert_store_is_reported_not_read_as_empty() {
    struct Unreadable;
    impl SecurityAlertsRepository for Unreadable {
        fn insert(&self, _: &SecurityAlert) -> DiagnosticsResult<()> {
            Ok(())
        }
        fn update_state(
            &self,
            _: &str,
            _: SecurityAlertState,
            _: u64,
            _: &str,
            _: i64,
        ) -> DiagnosticsResult<()> {
            Ok(())
        }
        fn list_by_state(&self, _: SecurityAlertState) -> DiagnosticsResult<Vec<SecurityAlert>> {
            Err(unreadable())
        }
        fn list_open(&self) -> DiagnosticsResult<Vec<SecurityAlert>> {
            Err(unreadable())
        }
        fn find_by_id(&self, _: &str) -> DiagnosticsResult<Option<SecurityAlert>> {
            Err(unreadable())
        }
    }
    fn unreadable() -> DiagnosticsError {
        DiagnosticsError::LogStorageUnavailable {
            reason: "security_alerts unreadable".into(),
        }
    }

    let dir = TempDir::new().expect("tempdir");
    let audit_dir = dir.path().join("audit");
    let logs_dir = dir.path().join("logs");
    std::fs::create_dir_all(&audit_dir).unwrap();
    std::fs::create_dir_all(&logs_dir).unwrap();
    let facade =
        ProductionDiagnosticsFacade::new(&logs_dir, &audit_dir, None, Arc::new(Unreadable), None);
    let status = facade.get_status(&DiagnosticsAudience::Machine);
    assert!(!status.security_status.alerts_readable);
    assert!(status.active_alerts.is_empty());
    assert!(!status.overall_healthy);
    // The wire carries the difference, so a client can tell it from an empty list.
    let wire = serde_json::to_value(&status).expect("serialise");
    assert_eq!(wire["security_status"]["alerts_readable"], false);
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

/// Writes one event per `(level, category, kind)`, `evt-0001` onwards, with
/// strictly increasing `created_at` (`1_745_000_000_000 + i * 1000`).
fn write_shaped_log_events(
    dir: &Path,
    shapes: &[(
        nrr_diagnostics::taxonomy::EventLevel,
        nrr_diagnostics::taxonomy::EventCategory,
        &str,
    )],
) {
    use nrr_diagnostics::event::LogEvent;
    use nrr_diagnostics::reason::service::STARTED;
    use std::io::Write;
    let date = nrr_diagnostics::audit::writer::local_date_string(std::time::SystemTime::now());
    let path = dir.join(format!("nrr_service_{date}-1.ndjson"));
    let mut file = std::fs::File::create(&path).expect("create log file");
    for (i, (level, category, kind)) in shapes.iter().enumerate() {
        let n = i as i64 + 1;
        let mut event = LogEvent::new(
            format!("evt-{n:04}"),
            1_745_000_000_000 + n * 1000,
            *level,
            STARTED,
        );
        event.category = *category;
        event.kind = (*kind).to_string();
        writeln!(file, "{}", event.to_ndjson().expect("serialize")).expect("write");
    }
}

/// Every page of a filtered listing, walked to the end.
fn all_pages(
    facade: &ProductionDiagnosticsFacade,
    filter: &LogEntryFilter,
    page_size: u32,
) -> Vec<Vec<LogEntryDto>> {
    let mut pages = Vec::new();
    let mut cursor = None;
    for _ in 0..100 {
        let page = facade
            .list_log_entries(
                filter,
                &PaginationParams {
                    cursor: cursor.clone(),
                    page_size,
                },
                &DiagnosticsAudience::Machine,
            )
            .expect("list");
        pages.push(page.items);
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => return pages,
        }
    }
    panic!("paging did not terminate");
}

/// The Logs view used to fetch unfiltered pages and hide rows itself, so
/// "warnings and errors" could show a page of nothing with more behind it.
/// Filtered on the service, every page is full of matches and paging reaches
/// all of them.
#[test]
fn a_level_filter_pages_through_every_match_and_nothing_else() {
    use nrr_diagnostics::taxonomy::{EventCategory, EventLevel};
    let dir = TempDir::new().expect("tempdir");
    let audit_dir = dir.path().join("audit");
    let logs_dir = dir.path().join("logs");
    std::fs::create_dir_all(&audit_dir).unwrap();
    std::fs::create_dir_all(&logs_dir).unwrap();
    let levels = [EventLevel::Warn, EventLevel::Info, EventLevel::Error];
    let shapes: Vec<_> = (0..12)
        .map(|i| (levels[i % 3], EventCategory::Service, "service.started"))
        .collect();
    write_shaped_log_events(&logs_dir, &shapes);
    let facade = make_facade(&audit_dir, &logs_dir);

    let filter = LogEntryFilter {
        level_min: Some("warn".into()),
        ..LogEntryFilter::default()
    };
    let pages = all_pages(&facade, &filter, 3);
    let (last, full) = pages.split_last().expect("at least one page");
    assert!(
        full.iter().all(|page| page.len() == 3),
        "every page but the last must be full"
    );
    assert!(!last.is_empty());
    let ids: Vec<String> = pages.iter().flatten().map(|e| e.event_id.clone()).collect();
    // evt-n has level levels[(n - 1) % 3]; Info is every third from evt-0002.
    let expected: Vec<String> = (1..=12)
        .rev()
        .filter(|n| (n - 1) % 3 != 1)
        .map(|n| format!("evt-{n:04}"))
        .collect();
    assert_eq!(ids, expected);

    let errors_since = LogEntryFilter {
        level_min: Some("error".into()),
        from_ms: Some(1_745_000_000_000 + 6 * 1000),
        ..LogEntryFilter::default()
    };
    let ids: Vec<String> = all_pages(&facade, &errors_since, 1)
        .into_iter()
        .flatten()
        .map(|e| e.event_id)
        .collect();
    assert_eq!(ids, vec!["evt-0012", "evt-0009", "evt-0006"]);
}

#[test]
fn category_is_exact_and_kind_is_a_substring() {
    use nrr_diagnostics::taxonomy::{EventCategory, EventLevel};
    let dir = TempDir::new().expect("tempdir");
    let audit_dir = dir.path().join("audit");
    let logs_dir = dir.path().join("logs");
    std::fs::create_dir_all(&audit_dir).unwrap();
    std::fs::create_dir_all(&logs_dir).unwrap();
    let shapes: Vec<_> = (0..9)
        .map(|i| {
            let category = if i % 2 == 0 {
                EventCategory::Apply
            } else {
                EventCategory::Service
            };
            let kind = if i % 3 == 0 {
                "apply.rollback_done"
            } else {
                "service.started"
            };
            (EventLevel::Info, category, kind)
        })
        .collect();
    write_shaped_log_events(&logs_dir, &shapes);
    let facade = make_facade(&audit_dir, &logs_dir);
    let ids = |filter: LogEntryFilter| -> Vec<String> {
        all_pages(&facade, &filter, 2)
            .into_iter()
            .flatten()
            .map(|e| e.event_id)
            .collect()
    };

    // Written index i is evt-(i + 1): Apply at even i, rollback at i % 3 == 0.
    assert_eq!(
        ids(LogEntryFilter {
            category: Some("apply".into()),
            ..LogEntryFilter::default()
        }),
        vec!["evt-0009", "evt-0007", "evt-0005", "evt-0003", "evt-0001"]
    );
    assert_eq!(
        ids(LogEntryFilter {
            kind: Some("rollback".into()),
            ..LogEntryFilter::default()
        }),
        vec!["evt-0007", "evt-0004", "evt-0001"]
    );
    assert_eq!(
        ids(LogEntryFilter {
            category: Some("service".into()),
            kind: Some("rollback".into()),
            ..LogEntryFilter::default()
        }),
        vec!["evt-0004"]
    );
    assert_eq!(
        ids(LogEntryFilter {
            kind: Some("Rollback".into()),
            ..LogEntryFilter::default()
        }),
        vec!["evt-0007", "evt-0004", "evt-0001"],
        "the kind match is case-insensitive"
    );
}

/// A misspelt filter used to be dropped and the whole log came back — the
/// opposite of what the person asked for.
#[test]
fn an_unknown_level_or_category_matches_nothing() {
    use nrr_diagnostics::taxonomy::{EventCategory, EventLevel};
    let dir = TempDir::new().expect("tempdir");
    let audit_dir = dir.path().join("audit");
    let logs_dir = dir.path().join("logs");
    std::fs::create_dir_all(&audit_dir).unwrap();
    std::fs::create_dir_all(&logs_dir).unwrap();
    write_shaped_log_events(
        &logs_dir,
        &[(EventLevel::Error, EventCategory::Service, "service.started")],
    );
    let facade = make_facade(&audit_dir, &logs_dir);
    for filter in [
        LogEntryFilter {
            category: Some("Service".into()),
            ..LogEntryFilter::default()
        },
        LogEntryFilter {
            category: Some(String::new()),
            ..LogEntryFilter::default()
        },
        LogEntryFilter {
            level_min: Some("fatal".into()),
            ..LogEntryFilter::default()
        },
    ] {
        let pages = all_pages(&facade, &filter, 50);
        assert!(pages.iter().all(Vec::is_empty), "{filter:?}");
        let recent = facade
            .recent_log_entries(&filter, 50, &DiagnosticsAudience::Machine)
            .expect("recent");
        assert!(recent.is_empty(), "{filter:?}");
    }
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
    let alerts = facade
        .list_alerts(AlertListFilter::Open, &DiagnosticsAudience::Machine)
        .expect("list");
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].alert_id, "alt-test");
    assert!(alerts[0].requires_action);
}

/// An alert about one user's stored rules reaches that user and an
/// administrator; another user learns only that an alert holds the edits, with
/// no SID and no revision of the owner's. Status and list agree.
#[test]
fn alerts_about_a_users_rules_are_scoped_to_that_user() {
    use nrr_diagnostics::audit::alert::SecurityAlertState::Active;
    use nrr_storage::migration::{open_connection, SqliteMigrationRunner};
    use nrr_storage::repository::MigrationRunner;
    const ALICE: &str = "S-1-5-21-1000-1000-1000-1001";
    const BOB: &str = "S-1-5-21-1000-1000-1000-1002";

    let dir = TempDir::new().expect("tmp");
    let conn = open_connection(&dir.path().join("state.db")).expect("open");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("migrate");
    let conn = Arc::new(std::sync::Mutex::new(runner.into_connection()));
    for (principal, revision_id) in [(ALICE, "rev-alice-1"), (BOB, "rev-bob-1")] {
        conn.lock()
            .expect("lock")
            .execute(
                "INSERT INTO revisions (
                    principal, revision_id, content_hash, rules_json, status, source,
                    correlation_id, created_at, activated_at
                 ) VALUES (?1, ?2, ?2, '{}', 'active', 'gui-rules-edit', 'c', 1, 1)",
                rusqlite::params![principal, revision_id],
            )
            .expect("seed revision");
    }
    let repo: Arc<dyn SecurityAlertsRepository> = Arc::new(InMemorySecurityAlertsRepository::new());
    let alert = |id: String, kind: &str, at: i64| SecurityAlert {
        alert_id: id,
        kind: kind.into(),
        state: Active,
        raised_event_seq: 0,
        raised_file: "bootstrap".into(),
        ack_event_seq: None,
        ack_file: None,
        resolved_event_seq: None,
        resolved_file: None,
        created_at: at,
        updated_at: at,
        reason_code: "integrity.db_row_hmac_mismatch".into(),
    };
    for a in [
        alert("alt-keyreset-1".into(), "key_reset_with_existing_data", 1),
        alert(
            format!("alt-dbtamper-pointer:{BOB}@f1"),
            "db_tamper_detected",
            2,
        ),
        alert("alt-dbtamper-rev-bob-1@f2".into(), "db_tamper_detected", 3),
        alert(
            "alt-dbtamper-rev-alice-1@f3".into(),
            "db_tamper_detected",
            4,
        ),
    ] {
        repo.insert(&a).expect("insert");
    }
    let facade = ProductionDiagnosticsFacade::new(
        dir.path(),
        dir.path(),
        None,
        repo,
        Some(Arc::clone(&conn)),
    );

    let alice = DiagnosticsAudience::Principal(ALICE.into());
    let listed = facade
        .list_alerts(AlertListFilter::All, &alice)
        .expect("list");
    let mut ids: Vec<&str> = listed.iter().map(|a| a.alert_id.as_str()).collect();
    ids.sort_unstable();
    assert_eq!(
        ids,
        [
            "alt-dbtamper-rev-alice-1@f3",
            "alt-keyreset-1",
            crate::alert_audience::OTHER_PRINCIPAL_ALERT_ID,
        ]
    );
    let status = facade.get_status(&alice);
    assert_eq!(status.security_status.active_alert_count, 3);
    let wire = serde_json::to_string(&(listed, status)).expect("json");
    assert!(!wire.contains(BOB) && !wire.contains("rev-bob"), "{wire}");

    let everything = facade.get_status(&DiagnosticsAudience::Machine);
    assert_eq!(everything.active_alerts.len(), 4);
    let bob = facade
        .list_alerts(
            AlertListFilter::Open,
            &DiagnosticsAudience::Principal(BOB.into()),
        )
        .expect("list");
    assert_eq!(
        bob.len(),
        4,
        "Bob's two, the machine's, and one for Alice's"
    );
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

/// A name probed without an address is blocked when a literal-IP Block names
/// one of its cached addresses, however narrowly a name rule routes it.
#[test]
fn a_literal_ip_block_on_a_cached_address_vetoes_the_name_probe() {
    use nrr_domain::canonical::{
        CanonicalAddressMatch, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet,
    };
    use nrr_domain::decision_matching::{RequestedRouteDecision, ZonePriorityPolicy};
    use nrr_domain::{RouteBehaviorMode, RuleAction, RuleId};
    use std::net::{IpAddr, Ipv4Addr};

    let rule = |id: &str, m: CanonicalAddressMatch, action: RuleAction| CanonicalRule {
        id: RuleId(id.into()),
        enabled: true,
        address_match: Some(m),
        app_match: None,
        comment: String::new(),
        action,
        origin: None,
    };
    let blocked = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let other = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
    let book = CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(vec![rule(
            "r-exact",
            CanonicalAddressMatch::ExactFqdn("a.example".into()),
            RuleAction::Route,
        )]),
        secondary: CanonicalRuleSet::from_rules(vec![rule(
            "b-ip",
            CanonicalAddressMatch::ExactIp(blocked),
            RuleAction::Block,
        )]),
    };
    let probe = |ips: &[IpAddr]| {
        literal_block_veto(
            &book,
            "a.example",
            ips,
            None,
            ZonePriorityPolicy::default(),
            RouteBehaviorMode::PreferPrimary,
        )
    };

    let (ip, decision) = probe(&[other, blocked]).expect("the cached blocked address vetoes");
    assert_eq!(ip, blocked);
    let RequestedRouteDecision::MatchedRoute { candidate } = decision else {
        panic!("a veto is a matched Block");
    };
    assert_eq!(candidate.rule_id.as_str(), "b-ip");
    assert_eq!(candidate.action, RuleAction::Block);

    // Positive control: without the blocked address in the cache, no veto.
    assert!(probe(&[other]).is_none());
    assert!(probe(&[]).is_none());
}

/// The engine still names the rule that would win, but a winner enforcement
/// skips for its shape must not read as enforced.
#[test]
fn a_winner_enforcement_cannot_carry_out_is_not_reported_as_enforced() {
    use nrr_shared::rules_json::{
        to_canonical_string, AddressMatchDto, AppMatchDto, AppPatternDto, CanonicalRulesJsonV1,
        RuleDto, RULES_JSON_SCHEMA_VERSION,
    };
    use nrr_storage::migration::{open_connection, SqliteMigrationRunner};
    use nrr_storage::repository::MigrationRunner;

    let probe = |with_app: bool| {
        let dir = TempDir::new().expect("tmp");
        let conn = open_connection(&dir.path().join("state.db")).expect("open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        let conn = Arc::new(std::sync::Mutex::new(runner.into_connection()));
        let rules_json = to_canonical_string(&CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![],
            secondary: vec![RuleDto {
                id: "R-0001".into(),
                enabled: true,
                address_match: Some(AddressMatchDto::ExactFqdn {
                    value: "host.example".into(),
                }),
                app_match: with_app.then(|| AppMatchDto {
                    pattern: AppPatternDto::Exact {
                        value: "app.exe".into(),
                    },
                    include_child_processes: false,
                }),
                comment: String::new(),
                action: nrr_shared::rules_json::RuleAction::Route,
                origin: None,
            }],
        })
        .expect("serialise");
        conn.lock()
            .expect("lock")
            .execute(
                "INSERT INTO revisions (
                    principal, revision_id, content_hash, rules_json, status, source,
                    correlation_id, created_at, activated_at
                 ) VALUES (?1, 'rev-1', 'h', ?2, 'active', 'gui-rules-edit', 'c', 1, 1)",
                rusqlite::params![nrr_storage::BASELINE_PRINCIPAL, rules_json],
            )
            .expect("seed active revision");
        let alerts: Arc<dyn SecurityAlertsRepository> =
            Arc::new(InMemorySecurityAlertsRepository::new());
        let facade =
            ProductionDiagnosticsFacade::new(dir.path(), dir.path(), None, alerts, Some(conn));
        let q = ExplainQuery::Synthetic {
            input_sample: nrr_diagnostics::explain::RuntimeInputSample::new()
                .with_hostname("host.example")
                .with_process("app.exe"),
        };
        facade
            .get_explain(&q, ExplainDetailLevel::Diagnostics, "")
            .expect("explain")
            .final_action_section
            .expect("final action")
    };

    let combined = probe(true);
    assert_eq!(combined.route_role.as_deref(), Some("secondary"));
    assert_eq!(
        combined.reason_key,
        "diag.explain.reason.rule-shape-not-enforced"
    );
    // Positive control: the same rule without the application is enforced.
    let plain = probe(false);
    assert_eq!(
        plain.reason_key,
        "diag.explain.reason.rule-matched-exact-fqdn"
    );
}

/// The writer opens a new file on every start, so checking only the newest
/// file shrank the window to "since the last boot": an edit in the middle of
/// yesterday's file went unnoticed. The whole chain in retention is checked.
#[test]
fn an_edit_in_an_older_audit_file_is_caught() {
    let dir = TempDir::new().expect("tempdir");
    let audit_dir = dir.path().join("audit");
    let logs_dir = dir.path().join("logs");
    std::fs::create_dir_all(&logs_dir).unwrap();
    for suffix in ["1", "2", "3"] {
        write_audit_event(&audit_dir, suffix);
    }
    let facade = make_facade(&audit_dir, &logs_dir);
    assert!(
        facade
            .get_status(&DiagnosticsAudience::Machine)
            .security_status
            .audit_chain_ok,
        "positive control: an untouched trail verifies"
    );

    let files = AuditReader::new(&audit_dir).list_files();
    assert_eq!(files.len(), 3);
    let middle = std::fs::read_to_string(&files[1]).expect("read");
    let written_at = std::fs::metadata(&files[1])
        .and_then(|m| m.modified())
        .expect("mtime");
    std::fs::write(&files[1], middle.replace("rev-1", "rev-9")).expect("tamper");
    // Same length, and the time put back: nothing but the bytes tells the
    // edit from the file already verified.
    std::fs::File::options()
        .write(true)
        .open(&files[1])
        .and_then(|f| f.set_modified(written_at))
        .expect("put the time back");

    assert!(
        !facade
            .get_status(&DiagnosticsAudience::Machine)
            .security_status
            .audit_chain_ok,
        "an edited older file must fail verification"
    );
}

/// The revision line of the status card is the caller's own: a user sees
/// their active revision (or the baseline they read through to) and their own
/// candidates, never another user's; the machine audience sees everything.
#[test]
fn the_status_revision_summary_follows_the_audience() {
    use nrr_storage::migration::{open_connection, SqliteMigrationRunner};
    use nrr_storage::repository::MigrationRunner;
    const ALICE: &str = "S-1-5-21-1000-1000-1000-1001";
    const BOB: &str = "S-1-5-21-1000-1000-1000-1002";
    const CAROL: &str = "S-1-5-21-1000-1000-1000-1003";

    let dir = TempDir::new().expect("tmp");
    let conn = open_connection(&dir.path().join("state.db")).expect("open");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("migrate");
    let conn = Arc::new(std::sync::Mutex::new(runner.into_connection()));
    for (principal, revision_id, status, at) in [
        (nrr_storage::BASELINE_PRINCIPAL, "rev-base", "active", 1),
        (ALICE, "rev-alice", "active", 2),
        (BOB, "rev-bob", "active", 3),
        (ALICE, "cand-alice", "candidate", 4),
        (BOB, "cand-bob-1", "candidate", 5),
        (BOB, "cand-bob-2", "candidate", 6),
    ] {
        conn.lock()
            .expect("lock")
            .execute(
                "INSERT INTO revisions (
                    principal, revision_id, content_hash, rules_json, status, source,
                    correlation_id, created_at, activated_at
                 ) VALUES (?1, ?2, ?2, '{}', ?3, 'gui-rules-edit', 'c', ?4, ?4)",
                rusqlite::params![principal, revision_id, status, at],
            )
            .expect("seed revision");
    }
    let alerts: Arc<dyn SecurityAlertsRepository> =
        Arc::new(InMemorySecurityAlertsRepository::new());
    let facade = ProductionDiagnosticsFacade::new(dir.path(), dir.path(), None, alerts, Some(conn));
    let summary = |audience: DiagnosticsAudience| {
        let health = facade.get_status(&audience).service_health;
        (health.active_revision_id, health.pending_changes)
    };

    assert_eq!(
        summary(DiagnosticsAudience::Principal(ALICE.into())),
        (Some("rev-alice".into()), 1)
    );
    assert_eq!(
        summary(DiagnosticsAudience::Principal(CAROL.into())),
        (Some("rev-base".into()), 0),
        "an undiverged user runs the baseline"
    );
    assert_eq!(
        summary(DiagnosticsAudience::Machine),
        (Some("rev-bob".into()), 3)
    );
}
