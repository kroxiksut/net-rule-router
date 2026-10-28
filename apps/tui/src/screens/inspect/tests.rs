#![allow(clippy::expect_used)]

//! The trace, cache and diagnostics screens on the scripted service: full
//! screen snapshots, line-mode transcripts, and the operations each action
//! sends.

use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use nrr_client_logic::conn_trace::TraceGrouping;
use nrr_ipc_client::{ConnectionStatus, IpcClient};
use nrr_shared::ipc::IpcOperationName;
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use serde_json::{json, Value};

use crate::full::{draw, handle_key, RenderOptions};
use crate::link::Link;
use crate::plain::PlainSession;
use crate::screens::settings::prefs;
use crate::screens::ScreenId;
use crate::state::AppState;
use crate::testing::{app_at, assert_snapshot, texts_en, FakeService, Fixture, Scratch};

const PLAIN: RenderOptions = RenderOptions {
    colour: false,
    ascii: true,
};

/// 2026-10-06 12:00:00 UTC.
const NOON: i64 = 1_791_288_000_000;

fn trace_row(process: &str, remote: &str, egress: &str, verdict: &str, hosts: &[&str]) -> Value {
    json!({
        "process": process,
        "process_path": "",
        "proto": "tcp",
        "local": "192.0.2.10:50000",
        "remote": remote,
        "egress_role": egress,
        "egress_ifindex": 7,
        "verdict": verdict,
        "blocked_by": if verdict == "block" { "netrulerouter" } else { "" },
        "block_reason": if verdict == "block" { "blocked-by-rule" } else { "" },
        "expected_route": "",
        "observed_at_ms": NOON,
        "relay_for": "",
        "rule_host": "",
        "remote_hosts": hosts,
        "remote_host_count": hosts.len(),
        "remote_host_floor": "",
        "remote_fake_ip": false
    })
}

fn cache_row(host: &str, ip: &str, route: &str) -> Value {
    json!({
        "hostname": host,
        "ip": ip,
        "freshness": "fresh",
        "source": "dns",
        "resolved_at_ms": NOON,
        "expires_at_ms": NOON + 3_600_000,
        "expected_route": route,
        "rule_match_kind": "",
        "fake_ip": ""
    })
}

fn alert() -> Value {
    json!({
        "alert_id": "alt-1",
        "kind": "db_tamper_detected",
        "state": "active",
        "created_at": NOON,
        "updated_at": NOON,
        "reason_code": "integrity.revision_signature",
        "raised_file": "audit-2026-10-06.ndjson",
        "requires_action": true
    })
}

fn diagnostics_status() -> Value {
    json!({
        "overall_healthy": false,
        "service_health": {
            "state": "running",
            "active_revision_id": "rev-7",
            "pending_changes": 0,
            "start_relative_to_sign_in": "before",
            "start_sign_in_gap_ms": 2400
        },
        "security_status": {
            "audit_chain_ok": true,
            "active_alert_count": 1,
            "audit_write_healthy": true,
            "alerts_readable": true
        },
        "active_alerts": [alert()],
        "cache_health": { "entry_count": 42, "healthy": true },
        "log_health": {
            "dir_writable": true,
            "total_size_bytes": 1024,
            "audit_size_bytes": 512,
            "file_count": 3,
            "dropped_count": 0,
            "last_cleanup_at": null
        },
        "stale": false,
        "origin": "service"
    })
}

fn outage_row(process: &str, ip: &str, port: u16, host: &str, rule_host: &str) -> Value {
    json!({
        "process": process,
        "process-path": if process == "browser.exe" { "/opt/example/browser.exe" } else { "" },
        "remote-ip": ip,
        "remote-port": port,
        "host": host,
        "rule-host": rule_host,
        "first-seen-ms": NOON - 540_000,
        "last-seen-ms": NOON - 60_000,
        "attempts": 12
    })
}

/// An outage answer with three rows; `episode` null for none.
fn outage(episode: Value, omitted: u32) -> Value {
    json!({
        "episode": episode,
        "entries": [
            outage_row("browser.exe", "203.0.113.5", 443, "video.example.com", "example.com"),
            outage_row("updater.exe", "2001:db8::7", 443, "", "cdn.example.net"),
            outage_row("?", "198.51.100.9", 0, "", ""),
        ],
        "omitted": omitted,
        "redacted": false,
        "observer-active": true,
        "gui-stream-enabled": true
    })
}

/// A service with an answer for every operation the screens use.
fn service() -> FakeService {
    let fake = FakeService::new(ConnectionStatus::Connected);
    let mut trace: Vec<Value> = (0..12)
        .map(|i| {
            trace_row(
                "browser.exe",
                &format!("203.0.113.{}:443", i + 1),
                if i % 2 == 0 { "primary" } else { "secondary" },
                "permit",
                &["site.example"],
            )
        })
        .collect();
    trace.push(trace_row(
        "app.exe",
        "198.51.100.9:443",
        "primary",
        "block",
        &[],
    ));
    trace.push(trace_row(
        "lan.exe",
        "192.168.1.5:445",
        "primary",
        "permit",
        &[],
    ));
    fake.answer(
        IpcOperationName::ConnTraceEntriesList,
        json!({
            "page": { "items": trace, "next_cursor": null, "total_count": 14, "stale": false },
            "redacted": false,
            "observer-active": true,
            "gui-stream-enabled": true
        }),
    );
    let cache: Vec<Value> = (0..12)
        .map(|i| {
            cache_row(
                &format!("host{i}.example.com"),
                &format!("192.0.2.{}", i + 20),
                if i < 3 { "secondary" } else { "" },
            )
        })
        .collect();
    fake.answer(
        IpcOperationName::CacheEntriesList,
        json!({
            "page": { "items": cache, "next_cursor": null, "total_count": 12, "stale": false },
            "redacted": false
        }),
    );
    fake.answer(
        IpcOperationName::CacheClear,
        json!({ "resolutions-removed": 3, "negative-cache-removed": 0, "dry-run": false,
                "os-cache-flushed": null }),
    );
    fake.answer(
        IpcOperationName::ServiceHealthGet,
        json!({ "service-state": "running", "worst-severity": "ok", "active-revision-id": "rev-7",
                "components": [] }),
    );
    fake.answer(
        IpcOperationName::SnapshotDiagnosticsGet,
        json!({ "status": diagnostics_status() }),
    );
    fake.answer(
        IpcOperationName::ExplainGet,
        json!({
            "compact": { "input": "site.example", "route": "secondary",
                         "reason-key": "diag.explain.reason.blocked-by-ip-rule" },
            "full": { "lookup_section": { "selected_ip": "203.0.113.2" } }
        }),
    );
    // One answer serves the dry-run and the confirm: each reads its own fields.
    fake.answer(
        IpcOperationName::MutationSubmit,
        json!({
            "review-summary": { "diff-summary": "", "provenance": "", "risk-level": "low",
                                "requires-review": false, "changed-fields": [] },
            "confirmation-token": "tok-1",
            "review-risk-level": "low",
            "unverified-rows": [{
                "row-kind": "revision", "principal": "S-1-5-21-0", "revision-id": "rev-7",
                "content-hash": "00", "baseline": false, "created-at": 1_791_280_000,
                "source": "gui-rules-edit", "status": "active", "rule-count": 12
            }],
            "operation-id": "op-1"
        }),
    );
    fake.answer(
        IpcOperationName::OperationStatusGet,
        json!({ "state": "completed" }),
    );
    fake.answer(
        IpcOperationName::LogsList,
        json!({
            "items": [{
                "event_id": "e1", "created_at": NOON, "level": "info", "category": "dns",
                "kind": "dns.refresh", "message_key": "diag.event.dns-refresh-tick",
                "message": "DNS refresh", "has_payload": false, "correlation_summary": [],
                "args": { "succeeded": "12", "attempted": "14" }
            }, {
                "event_id": "e2", "created_at": NOON - 1000, "level": "warn", "category": "service",
                "kind": "service.slow", "message_key": "", "message": "Apply took long",
                "has_payload": false, "correlation_summary": []
            }],
            "next_cursor": null, "total_count": 2, "stale": false
        }),
    );
    fake.answer(
        IpcOperationName::AuditList,
        json!({
            "items": [{
                "event_id": "a2", "seq": 8, "kind": "protection_override_revoked",
                "created_at": NOON, "result": "success",
                "reason_code": "protection.override_revoked", "revision_id": null,
                "has_payload_summary": true, "cause": "crash-loop"
            }, {
                "event_id": "a1", "seq": 7, "kind": "protection_override_revoked",
                "created_at": NOON - 1000, "result": "success",
                "reason_code": "protection.override_revoked", "revision_id": "rev-7",
                "has_payload_summary": true, "cause": "some-new-cause"
            }],
            "next_cursor": null, "total_count": 2, "stale": false
        }),
    );
    fake.answer(
        IpcOperationName::ConnTraceOutageBlocksList,
        outage(json!({ "since-unix-ms": NOON - 600_000 }), 0),
    );
    fake.answer(
        IpcOperationName::DiagnosticsExportArchive,
        json!({ "archive-path": "/nonexistent/archives/nrr-diag.zip", "size-bytes": 2048,
                "generated-at-ms": NOON }),
    );
    fake
}

/// The trace flat and its paths read as Windows ones, whatever the test
/// machine; the grouping tests below choose their own.
fn connected() -> AppState {
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    app.settings.prefs.trace_grouping = TraceGrouping::None;
    app.inspect.trace.os = "windows";
    app
}

/// Run what the screens queued, and what their answers queued in turn.
fn settle(app: &mut AppState, client: &dyn IpcClient) {
    loop {
        let jobs = app.outbox.take();
        if jobs.is_empty() {
            return;
        }
        for job in jobs {
            (job(client).0)(app);
        }
    }
}

fn key(app: &mut AppState, code: KeyCode) {
    handle_key(app, KeyEvent::new(code, KeyModifiers::NONE), &texts_en());
}

fn render(app: &AppState, width: u16, height: u16) -> String {
    let texts = texts_en();
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
    terminal
        .draw(|frame| draw(frame, app, &texts, PLAIN, Instant::now()))
        .expect("draw");
    let buffer = terminal.backend().buffer();
    let mut out = String::new();
    for y in 0..height {
        let row: String = (0..width).map(|x| buffer[(x, y)].symbol()).collect();
        out.push_str(row.trim_end());
        out.push('\n');
    }
    out
}

fn open(app: &mut AppState, fake: &FakeService, screen: ScreenId) {
    app.open(screen);
    settle(app, fake);
    // The view records what it listed; keys act on that.
    let _ = render(app, 100, 40);
}

#[test]
fn the_trace_hides_blocked_and_local_rows_and_pages() {
    let fake = service();
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Trace);
    let picture = render(&app, 100, 40);
    assert!(picture.contains("Shown: 12 of 14."), "{picture}");
    assert!(picture.contains("Rows 1–10 of 12."), "{picture}");
    assert!(
        !picture.contains("app.exe"),
        "blocked rows start hidden:\n{picture}"
    );
    assert_snapshot("trace-100x40", &picture);

    key(&mut app, KeyCode::Tab);
    key(&mut app, KeyCode::PageDown);
    assert!(render(&app, 100, 40).contains("Rows 11–12 of 12."));
    key(&mut app, KeyCode::Char('b'));
    let _ = render(&app, 100, 40);
    key(&mut app, KeyCode::End);
    let picture = render(&app, 100, 40);
    assert!(picture.contains("Show blocked: Yes"), "{picture}");
    assert!(picture.contains("Rows 11–13 of 13."), "{picture}");
    assert!(picture.contains("Blocked (NetRuleRouter)"), "{picture}");
}

#[test]
fn why_this_route_runs_the_probe_in_diagnostics() {
    let fake = service();
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Trace);
    key(&mut app, KeyCode::Tab);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Enter);
    settle(&mut app, &fake);
    assert_eq!(app.screen, ScreenId::Diagnostics);
    let picture = render(&app, 100, 40);
    assert!(
        picture.contains("site.example  →  Additional — Allowed"),
        "{picture}"
    );
    assert!(picture.contains("(203.0.113.2)"), "{picture}");
    assert!(fake.operations().contains(&IpcOperationName::ExplainGet));
}

#[test]
fn a_system_dns_left_redirected_tells_the_user_how_to_repair_it() {
    let fake = service();
    fake.answer(
        IpcOperationName::ServiceHealthGet,
        json!({ "service-state": "degraded", "worst-severity": "degraded",
                "components": [{
                    "component": "apply", "severity": "degraded",
                    "message": "task 'dns-resolver' ended: system DNS could not be restored: x"
                }] }),
    );
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Diagnostics);
    let picture = render(&app, 200, 40);
    assert!(picture.contains("System DNS could not"), "{picture}");
}

/// The user is told the saved rules did not read and the last applied ones
/// hold, in their words rather than the service's English line.
#[test]
fn an_unreadable_rule_book_is_said_and_the_last_rules_hold() {
    let fake = service();
    fake.answer(
        IpcOperationName::ServiceHealthGet,
        json!({ "service-state": "degraded", "worst-severity": "degraded",
                "components": [{
                    "component": "policy", "severity": "degraded",
                    "message": format!(
                        "{}; the last applied rules stay in force (1 account(s))",
                        nrr_shared::ipc_payloads::RULES_BOOK_UNREADABLE
                    )
                }] }),
    );
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Diagnostics);
    let picture = render(&app, 200, 40);
    assert!(picture.contains("could not read saved rules"), "{picture}");
    assert!(
        !picture.contains(nrr_shared::ipc_payloads::RULES_BOOK_UNREADABLE),
        "the service's own line is not repeated: {picture}"
    );
}

#[test]
fn clearing_the_cache_asks_first() {
    let fake = service();
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Cache);
    assert_snapshot("cache-100x40", &render(&app, 100, 40));

    key(&mut app, KeyCode::Char('c'));
    assert!(render(&app, 100, 40).contains("Clear the app cache?"));
    key(&mut app, KeyCode::Char('n'));
    settle(&mut app, &fake);
    assert!(!fake.operations().contains(&IpcOperationName::CacheClear));

    key(&mut app, KeyCode::Char('c'));
    key(&mut app, KeyCode::Char('y'));
    settle(&mut app, &fake);
    assert!(fake.operations().contains(&IpcOperationName::CacheClear));
    let picture = render(&app, 100, 40);
    assert!(
        picture.contains("Cache cleared: 3 resolution(s) removed."),
        "{picture}"
    );
}

/// The window's cache filters narrow the loaded rows one press at a time, and
/// `b` asks the service to seed the cache from browser history.
#[test]
fn the_cache_filters_narrow_the_rows_and_b_seeds_from_history() {
    let fake = service();
    fake.answer(
        IpcOperationName::SeedFromBrowserHistory,
        json!({ "started": true, "already-running": false }),
    );
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Cache);
    let text = view_text(&app, ScreenId::Cache);
    assert!(
        text.contains("Shown: All sources · Any freshness · All routes"),
        "{text}"
    );

    // Route: all → primary (none in the fixture) → secondary (three rows).
    key(&mut app, KeyCode::Char('w'));
    let text = view_text(&app, ScreenId::Cache);
    assert!(text.contains("No entries match your search"), "{text}");
    key(&mut app, KeyCode::Char('w'));
    let text = view_text(&app, ScreenId::Cache);
    assert!(text.contains("host2.example.com"), "{text}");
    assert!(!text.contains("host5.example.com"), "{text}");
    // Freshness: every fixture row is fresh, so "stale" keeps none.
    key(&mut app, KeyCode::Char('f'));
    key(&mut app, KeyCode::Char('f'));
    assert!(!view_text(&app, ScreenId::Cache).contains("host2.example.com"));

    key(&mut app, KeyCode::Char('b'));
    settle(&mut app, &fake);
    assert!(fake
        .operations()
        .contains(&IpcOperationName::SeedFromBrowserHistory));
    assert!(view_text(&app, ScreenId::Cache).contains("Import started"));
}

/// Another surface acknowledging an alert reaches this screen as a push; the
/// list is re-read on the spot, and only while it is the screen on show.
#[test]
fn an_alert_change_elsewhere_re_reads_the_list_on_screen() {
    let fake = service();
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Diagnostics);
    let reads_before = fake
        .operations()
        .iter()
        .filter(|op| **op == IpcOperationName::SnapshotDiagnosticsGet)
        .count();

    fn alerts_changed() -> crate::backend::BackendEvent {
        crate::backend::BackendEvent::Push(crate::backend::PushEvent::Status(Box::new(
            nrr_shared::ipc_payloads::StatusUpdateEvent::SecurityAlertsChanged,
        )))
    }
    app.apply(alerts_changed(), &texts_en(), Instant::now());
    settle(&mut app, &fake);
    let reads_after = fake
        .operations()
        .iter()
        .filter(|op| **op == IpcOperationName::SnapshotDiagnosticsGet)
        .count();
    assert_eq!(reads_after, reads_before + 1, "the alert list is re-read");

    app.open(ScreenId::Status);
    app.outbox.take();
    app.apply(alerts_changed(), &texts_en(), Instant::now());
    assert!(
        app.outbox.take().is_empty(),
        "nothing is read for a screen that is not on show"
    );
}

fn reads_of(fake: &FakeService, op: IpcOperationName) -> usize {
    fake.operations().iter().filter(|o| **o == op).count()
}

fn service_restarts(app: &mut AppState, fake: &FakeService) {
    for link in [Link::Stopped, Link::Connected] {
        app.apply(
            crate::backend::BackendEvent::Link(link),
            &texts_en(),
            Instant::now(),
        );
    }
    settle(app, fake);
}

/// A restarted service may have restarted its audit chain or cleared alerts
/// and cache entries: what was read before is read again, not kept unmarked.
#[test]
fn diagnostics_and_cache_are_read_again_after_the_service_comes_back() {
    let fake = service();
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Diagnostics);
    let before = reads_of(&fake, IpcOperationName::SnapshotDiagnosticsGet);
    service_restarts(&mut app, &fake);
    assert_eq!(
        reads_of(&fake, IpcOperationName::SnapshotDiagnosticsGet),
        before + 1
    );

    open(&mut app, &fake, ScreenId::Cache);
    let before = reads_of(&fake, IpcOperationName::CacheEntriesList);
    service_restarts(&mut app, &fake);
    assert_eq!(
        reads_of(&fake, IpcOperationName::CacheEntriesList),
        before + 1
    );
    // A screen not on show is read again once it is shown.
    let before = reads_of(&fake, IpcOperationName::SnapshotDiagnosticsGet);
    open(&mut app, &fake, ScreenId::Diagnostics);
    assert_eq!(
        reads_of(&fake, IpcOperationName::SnapshotDiagnosticsGet),
        before + 1
    );
}

fn alert_with(id: &str, reason: &str) -> Value {
    let mut a = alert();
    a["alert_id"] = json!(id);
    a["reason_code"] = json!(reason);
    a
}

fn answer_alerts(fake: &FakeService, alerts: Vec<Value>) {
    let mut status = diagnostics_status();
    status["security_status"]["active_alert_count"] = json!(alerts.len());
    status["active_alerts"] = json!(alerts);
    fake.answer(
        IpcOperationName::SnapshotDiagnosticsGet,
        json!({ "status": status }),
    );
}

fn alerts_changed(app: &mut AppState, fake: &FakeService) {
    app.apply(
        crate::backend::BackendEvent::Push(crate::backend::PushEvent::Status(Box::new(
            nrr_shared::ipc_payloads::StatusUpdateEvent::SecurityAlertsChanged,
        ))),
        &texts_en(),
        Instant::now(),
    );
    settle(app, fake);
}

/// An alert raised elsewhere lands ahead of the chosen one: the cursor stays
/// on its alert, so `a` never answers the newcomer.
#[test]
fn the_alert_cursor_stays_on_its_alert_when_the_list_changes() {
    let fake = service();
    answer_alerts(
        &fake,
        vec![
            alert_with("alt-1", "first.reason"),
            alert_with("alt-2", "second.reason"),
        ],
    );
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Diagnostics);
    answer_alerts(
        &fake,
        vec![
            alert_with("alt-0", "newcomer.reason"),
            alert_with("alt-1", "first.reason"),
            alert_with("alt-2", "second.reason"),
        ],
    );
    alerts_changed(&mut app, &fake);
    let picture = render(&app, 100, 40);
    let marked = picture
        .lines()
        .find(|l| l.contains("> ") && l.contains(".reason"))
        .expect("a marked alert");
    assert!(marked.contains("first.reason"), "{picture}");
}

/// Line mode: `a 1` names the alert printed first, wherever it went since.
#[test]
fn a_typed_alert_number_names_the_alert_as_printed() {
    let fake = service();
    answer_alerts(
        &fake,
        vec![
            alert_with("alt-1", "first.reason"),
            alert_with("alt-2", "second.reason"),
        ],
    );
    let texts = texts_en();
    let mut app = connected();
    let mut session = PlainSession::new(Vec::new());
    session.start(&app, &texts).expect("start");
    session.input("9", &mut app, &texts).expect("open");
    settle(&mut app, &fake);
    session.input("", &mut app, &texts).expect("print again");
    answer_alerts(
        &fake,
        vec![
            alert_with("alt-0", "newcomer.reason"),
            alert_with("alt-1", "first.reason"),
            alert_with("alt-2", "second.reason"),
        ],
    );
    alerts_changed(&mut app, &fake);
    session.input("a 1", &mut app, &texts).expect("acknowledge");
    settle(&mut app, &fake);
    let sent =
        serde_json::to_string(&fake.sent(IpcOperationName::MutationSubmit)).expect("requests");
    assert!(sent.contains("alt-1"), "{sent}");
    assert!(!sent.contains("alt-0"), "{sent}");
}

/// From the menu no alert is chosen in sight: `a` there only gives the list
/// the focus, the next `a` acts on the marked alert.
#[test]
fn acknowledging_from_the_menu_first_gives_the_list_the_focus() {
    let fake = service();
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Diagnostics);
    assert_eq!(app.focus, crate::state::Focus::Menu);
    key(&mut app, KeyCode::Char('a'));
    settle(&mut app, &fake);
    assert!(!render(&app, 100, 40).contains("Acknowledge security alert"));
    assert_eq!(app.focus, crate::state::Focus::Feed);
    key(&mut app, KeyCode::Char('a'));
    settle(&mut app, &fake);
    assert!(render(&app, 100, 40).contains("Acknowledge security alert"));
}

#[test]
fn an_alert_that_trusts_rule_sets_shows_them_before_acknowledging() {
    let fake = service();
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Diagnostics);
    assert_snapshot("diagnostics-100x40", &render(&app, 100, 40));

    key(&mut app, KeyCode::Tab);
    key(&mut app, KeyCode::Char('a'));
    settle(&mut app, &fake);
    let picture = render(&app, 100, 40);
    assert!(picture.contains("Acknowledge security alert"), "{picture}");
    assert!(picture.contains("12 rules"), "{picture}");
    assert!(
        !fake
            .operations()
            .contains(&IpcOperationName::OperationStatusGet),
        "nothing is confirmed before the answer"
    );

    key(&mut app, KeyCode::Char('y'));
    settle(&mut app, &fake);
    assert!(fake
        .operations()
        .contains(&IpcOperationName::OperationStatusGet));
    assert!(render(&app, 100, 40).contains("Security alert acknowledged."));
}

/// A broken audit chain offers the restart; the breaks it covers are shown
/// before anything is confirmed, and the confirm reports its outcome.
#[test]
fn a_broken_audit_chain_is_restarted_after_its_breaks_are_shown() {
    let fake = service();
    let mut status = diagnostics_status();
    status["security_status"]["audit_chain_ok"] = json!(false);
    fake.answer(
        IpcOperationName::SnapshotDiagnosticsGet,
        json!({ "status": status }),
    );
    fake.answer(
        IpcOperationName::MutationSubmit,
        json!({
            "review-summary": { "diff-summary": "", "provenance": "", "risk-level": "high",
                                "requires-review": true, "changed-fields": [] },
            "confirmation-token": "tok-2",
            "review-risk-level": "high",
            "audit-chain": {
                "break-count": 2,
                "breaks": [{ "kind": "hash-mismatch", "file": "audit-1.ndjson", "line": 7 }],
                "breaks-digest": "d1"
            },
            "operation-id": "op-2"
        }),
    );
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Diagnostics);
    let picture = render(&app, 120, 40);
    assert!(picture.contains("k: Restart audit chain"), "{picture}");

    key(&mut app, KeyCode::Char('k'));
    settle(&mut app, &fake);
    let text = view_text(&app, ScreenId::Diagnostics);
    assert!(text.contains("fails verification in 2 places"), "{text}");
    assert!(
        text.contains("audit-1.ndjson, line 7: record changed after it was written"),
        "{text}"
    );
    assert!(text.contains("Only the first 1 are listed."), "{text}");
    assert!(
        !fake
            .operations()
            .contains(&IpcOperationName::OperationStatusGet),
        "nothing is confirmed before the answer"
    );

    key(&mut app, KeyCode::Char('y'));
    settle(&mut app, &fake);
    let submits = fake.sent(IpcOperationName::MutationSubmit);
    assert!(
        submits
            .iter()
            .any(|s| s["payload"]["breaks-digest"] == json!("d1") && s["dry-run"] == json!(false)),
        "{submits:?}"
    );
    let text = view_text(&app, ScreenId::Diagnostics);
    assert!(text.contains("Audit chain restarted."), "{text}");
}

#[test]
fn the_archive_says_where_it_went() {
    let fake = service();
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Diagnostics);
    key(&mut app, KeyCode::Char('x'));
    settle(&mut app, &fake);
    let picture = render(&app, 120, 40);
    assert!(
        picture.contains("Archive saved: /nonexistent/archives/nrr-diag.zip (2.0 KiB)"),
        "{picture}"
    );
    assert!(picture.contains("this account cannot open it"), "{picture}");
}

#[test]
fn log_lines_are_translated_with_their_fields() {
    let fake = service();
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Diagnostics);
    key(&mut app, KeyCode::Char('l'));
    settle(&mut app, &fake);
    let picture = render(&app, 120, 30);
    assert!(
        picture.contains("DNS refresh: 12 of 14 names resolved"),
        "{picture}"
    );
    assert!(picture.contains("Apply took long"), "{picture}");
    assert_snapshot("logs-120x30", &picture);
}

/// An audit entry's cause is a service slug: it reads in words, and one the
/// locale does not know yet falls back to the slug.
#[test]
fn audit_entries_word_their_cause() {
    let fake = service();
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Diagnostics);
    key(&mut app, KeyCode::Char('l'));
    key(&mut app, KeyCode::Char('l'));
    settle(&mut app, &fake);
    assert!(fake.operations().contains(&IpcOperationName::AuditList));
    let text = view_text(&app, ScreenId::Diagnostics);
    assert!(text.contains("protection.override_revoked"), "{text}");
    assert!(
        text.contains("the service crashed several times in a row"),
        "{text}"
    );
    assert!(!text.contains("crash-loop"), "{text}");
    assert!(text.contains("some-new-cause · rev-7"), "{text}");

    let ru = crate::i18n::Texts::load(Some("ru"), &[]);
    let view = crate::screens::screen(ScreenId::Diagnostics).view(&app, &ru);
    let words: String = view
        .panels
        .iter()
        .flat_map(|panel| panel.lines.iter().map(|line| line.plain_text()))
        .collect();
    assert!(words.contains("серия падений службы"), "{words}");
}

/// Line mode: the screen, its commands, a page at a time.
fn transcript(answers: &[&str]) -> String {
    transcript_with(&service(), answers)
}

fn transcript_with(fake: &FakeService, answers: &[&str]) -> String {
    let texts = texts_en();
    let mut app = connected();
    let mut session = PlainSession::new(Vec::new());
    session.start(&app, &texts).expect("start");
    for answer in answers {
        session.input(answer, &mut app, &texts).expect("answer");
        settle(&mut app, fake);
        session.changed(&app, &texts).expect("changed");
    }
    String::from_utf8(session.into_inner()).expect("line mode writes UTF-8")
}

#[test]
fn the_trace_reads_a_page_at_a_time_in_line_mode() {
    let text = transcript(&["7", "", "n", "p", "d 2", "e 2"]);
    assert!(text.contains("n: next page (more)"), "{text}");
    assert!(text.contains("Rows 11–12 of 12."), "{text}");
    assert!(text.contains("Screen: Diagnostics and logs"), "{text}");
    assert!(!text.contains('\u{1b}'), "{text}");
    assert_snapshot("plain-trace", &text);
}

#[test]
fn line_mode_clears_the_cache_only_on_yes() {
    let text = transcript(&["8", "c", "x", "n", "o", "y"]);
    assert!(text.contains("Clear the app cache?"), "{text}");
    assert!(text.contains("Not understood: x"), "{text}");
    assert!(text.contains("Could not flush the OS DNS cache."), "{text}");
    assert_snapshot("plain-cache", &text);
}

#[test]
fn line_mode_acknowledges_explains_and_reads_the_log() {
    let text = transcript(&["9", "a 1", "y", "e example.com", "l", "v"]);
    assert!(text.contains("Security alert acknowledged."), "{text}");
    assert!(
        text.contains("DNS refresh: 12 of 14 names resolved"),
        "{text}"
    );
    assert!(text.contains("Level: Info"), "{text}");
    assert_snapshot("plain-diagnostics", &text);
}

/// A screen's words, panel by panel, without the wrapping of a terminal.
fn view_text(app: &AppState, id: ScreenId) -> String {
    let texts = texts_en();
    let view = crate::screens::screen(id).view(app, &texts);
    let mut out = String::new();
    for panel in &view.panels {
        out.push_str(&panel.title);
        out.push('\n');
        for line in &panel.lines {
            out.push_str(&line.plain_text());
            out.push('\n');
        }
    }
    out
}

fn outage_text(answer: Value) -> String {
    let fake = service();
    fake.answer(IpcOperationName::ConnTraceOutageBlocksList, answer);
    let mut app = connected();
    open(&mut app, &fake, ScreenId::OutageBlocks);
    view_text(&app, ScreenId::OutageBlocks)
}

#[test]
fn the_outage_list_names_what_was_blocked_while_the_route_is_down() {
    let fake = service();
    let mut app = connected();
    open(&mut app, &fake, ScreenId::OutageBlocks);
    let picture = render(&app, 140, 40);
    assert!(
        picture.contains("Blocked while the route was down"),
        "the menu shows the screen while it is open:\n{picture}"
    );
    assert_snapshot("outage-140x40", &picture);

    let text = view_text(&app, ScreenId::OutageBlocks);
    assert!(
        text.contains("The additional route has been down since 2026-10-06 11:50:00."),
        "{text}"
    );
    assert!(
        text.contains("Process | Remote | Attempts | First | Last"),
        "{text}"
    );
    assert!(
        text.contains(
            "browser.exe | video.example.com · 203.0.113.5:443 | 12 | 2026-10-06 11:51:00 | 2026-10-06 11:59:00"
        ),
        "{text}"
    );
    assert!(
        text.contains("updater.exe | cdn.example.net · [2001:db8::7]:443"),
        "the rule's host stands in for a missing name:\n{text}"
    );
    assert!(text.contains("? | 198.51.100.9 | 12"), "{text}");
    assert!(text.contains("3: Open interfaces and routes"), "{text}");
    assert!(text.contains("Path: /opt/example/browser.exe"), "{text}");

    key(&mut app, KeyCode::Tab);
    key(&mut app, KeyCode::Down);
    let text = view_text(&app, ScreenId::OutageBlocks);
    assert!(text.contains("Remote: cdn.example.net"), "{text}");
    assert!(!text.contains("Path:"), "{text}");
}

#[test]
fn an_ended_outage_says_when_and_offers_no_fix() {
    let text = outage_text(outage(
        json!({ "since-unix-ms": NOON - 600_000, "until-unix-ms": NOON }),
        0,
    ));
    assert!(
        text.contains("The last outage lasted from 2026-10-06 11:50:00 to 2026-10-06 12:00:00."),
        "{text}"
    );
    assert!(!text.contains("Open interfaces and routes"), "{text}");
}

#[test]
fn without_an_outage_the_screen_says_so() {
    let mut answer = outage(Value::Null, 0);
    answer["entries"] = json!([]);
    let text = outage_text(answer);
    assert!(
        text.contains("The additional route has not been down since the service started."),
        "{text}"
    );
    assert!(!text.contains("Nothing was blocked"), "{text}");
}

#[test]
fn an_outage_with_nothing_blocked_and_a_cut_list_are_said() {
    let mut answer = outage(json!({ "since-unix-ms": NOON }), 0);
    answer["entries"] = json!([]);
    let text = outage_text(answer);
    assert!(
        text.contains("Nothing was blocked during this outage."),
        "{text}"
    );

    let text = outage_text(outage(json!({ "since-unix-ms": NOON }), 2));
    assert!(
        text.contains("2 older entries did not fit in the list."),
        "{text}"
    );
}

#[test]
fn an_empty_list_that_cannot_be_filled_says_why() {
    let mut answer = outage(json!({ "since-unix-ms": NOON }), 0);
    answer["entries"] = json!([]);
    answer["observer-active"] = json!(false);
    let text = outage_text(answer.clone());
    assert!(
        text.contains("cannot tell which connections an outage blocked"),
        "{text}"
    );
    assert!(!text.contains("Nothing was blocked"), "{text}");

    answer["observer-active"] = json!(true);
    answer["gui-stream-enabled"] = json!(false);
    let text = outage_text(answer);
    assert!(
        text.contains("Showing the connection trace is switched off in Settings"),
        "{text}"
    );
    assert!(!text.contains("Nothing was blocked"), "{text}");
}

#[test]
fn o_on_the_trace_opens_the_outage_list_and_r_reads_it_again() {
    let fake = service();
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Trace);
    let picture = render(&app, 140, 40);
    assert!(!picture.contains("Blocked while the route was down"));
    key(&mut app, KeyCode::Char('o'));
    assert_eq!(app.screen, ScreenId::OutageBlocks);
    settle(&mut app, &fake);
    key(&mut app, KeyCode::Char('r'));
    settle(&mut app, &fake);
    let reads = fake
        .operations()
        .iter()
        .filter(|op| **op == IpcOperationName::ConnTraceOutageBlocksList)
        .count();
    assert_eq!(reads, 2);
}

#[test]
fn line_mode_reads_the_outage_list() {
    let text = transcript(&["7", "o", "", "d 2"]);
    assert!(
        text.contains("o: what was blocked while the additional route was down"),
        "{text}"
    );
    assert!(
        text.contains("Screen: Blocked while the route was down"),
        "{text}"
    );
    assert!(
        text.contains("Remote: cdn.example.net · [2001:db8::7]:443"),
        "{text}"
    );
    assert!(!text.contains('\u{1b}'), "{text}");
    assert_snapshot("plain-outage", &text);
}

/// An outage answer whose names never resolved, after the blocked rows.
fn outage_with_names(entries: Value) -> Value {
    let mut answer = outage(json!({ "since-unix-ms": NOON - 600_000 }), 0);
    answer["entries"] = entries;
    answer["unresolved-names"] = json!([{
        "name": "chat.example.com",
        "first-seen-ms": NOON - 300_000,
        "last-seen-ms": NOON - 30_000,
        "attempts": 5
    }]);
    answer
}

#[test]
fn a_name_that_did_not_resolve_is_listed_after_the_blocked_rows_and_marked() {
    let rows = outage(Value::Null, 0)["entries"].clone();
    let fake = service();
    fake.answer(
        IpcOperationName::ConnTraceOutageBlocksList,
        outage_with_names(rows),
    );
    let mut app = connected();
    open(&mut app, &fake, ScreenId::OutageBlocks);
    let text = view_text(&app, ScreenId::OutageBlocks);
    assert!(
        text.contains(
            "4. — | chat.example.com · did not resolve | 5 | 2026-10-06 11:55:00 | 2026-10-06 11:59:30"
        ),
        "{text}"
    );
    assert!(
        text.contains("Names marked “did not resolve” got no address"),
        "{text}"
    );

    key(&mut app, KeyCode::Tab);
    for _ in 0..3 {
        key(&mut app, KeyCode::Down);
    }
    let text = view_text(&app, ScreenId::OutageBlocks);
    assert!(
        text.contains("Remote: chat.example.com · did not resolve"),
        "{text}"
    );
    assert!(
        !text.contains("Process:"),
        "no program to name:
{text}"
    );

    let plain = transcript_with(&fake, &["7", "o", "", "d 4"]);
    assert!(
        plain.contains("Remote: chat.example.com · did not resolve"),
        "{plain}"
    );
}

/// Names alone are not "nothing was blocked".
#[test]
fn an_outage_with_only_names_does_not_say_nothing_was_blocked() {
    let text = outage_text(outage_with_names(json!([])));
    assert!(
        text.contains("chat.example.com · did not resolve"),
        "{text}"
    );
    assert!(!text.contains("Nothing was blocked"), "{text}");
}

#[test]
fn a_time_today_is_a_clock_time_and_another_day_carries_its_date() {
    assert_eq!(super::clock_time_at(NOON, NOON + 3_600_000), "12:00:00");
    assert_eq!(
        super::clock_time_at(NOON, NOON + 2 * 86_400_000),
        "2026-10-06 12:00:00"
    );
    assert_eq!(super::clock_time_at(0, NOON), "—");
}

/// A program named to fool the terminal and the eye: OSC 52 would write the
/// viewer's clipboard, U+202E turns `gnp.exe` into `exe.png`.
const HOSTILE_PROCESS: &str = "gnp\u{202E}.exe\u{1b}]52;c;aGk=\u{7}";

fn hostile_trace() -> FakeService {
    let fake = service();
    fake.answer(
        IpcOperationName::ConnTraceEntriesList,
        json!({
            "page": {
                "items": [trace_row(
                    HOSTILE_PROCESS,
                    "203.0.113.7:443",
                    "primary",
                    "permit",
                    &["exa\u{200B}mple.test"],
                )],
                "next_cursor": null,
                "total_count": 1,
                "stale": false
            },
            "redacted": false,
            "observer-active": true,
            "gui-stream-enabled": true
        }),
    );
    fake
}

/// A program on the additional route has its first connection to a new
/// address held while the address is learned. Shown as a block beside the
/// success, the user reads "it works but gets blocked"; a hold nothing
/// followed is a real block and stays one.
#[test]
fn a_held_first_connection_reads_as_the_one_that_went_through() {
    let held = |process: &str, at: i64| {
        let mut row = trace_row(process, "160.79.104.10:443", "primary", "block", &[]);
        row["block_reason"] = json!("route-unavailable");
        row["observed_at_ms"] = json!(at);
        row
    };
    let mut routed = trace_row(
        "claude.exe",
        "160.79.104.10:443",
        "secondary",
        "permit",
        &[],
    );
    routed["observed_at_ms"] = json!(NOON + 3_000);
    let fake = service();
    fake.answer(
        IpcOperationName::ConnTraceEntriesList,
        json!({
            "page": {
                "items": [routed, held("claude.exe", NOON), held("other.exe", NOON)],
                "next_cursor": null,
                "total_count": 3,
                "stale": false
            },
            "redacted": false,
            "observer-active": true,
            "gui-stream-enabled": true
        }),
    );
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Trace);
    key(&mut app, KeyCode::Tab);
    key(&mut app, KeyCode::Char('b'));
    let picture = render(&app, 140, 40);
    assert!(picture.contains("Shown: 2 of 2."), "{picture}");
    assert_eq!(
        picture.matches("Blocked (NetRuleRouter)").count(),
        1,
        "only the hold nothing followed stays a block:\n{picture}"
    );
    assert!(picture.contains("other.exe"), "{picture}");
    assert!(
        picture.contains("First connection held at"),
        "the routed row says it was held first:\n{picture}"
    );
}

#[test]
fn a_hostile_process_name_is_shown_with_dots_and_never_reaches_the_terminal() {
    use nrr_shared::display_text::needs_substitute;

    let fake = hostile_trace();
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Trace);
    let picture = render(&app, 100, 40);
    for line in picture.lines() {
        assert!(!line.chars().any(needs_substitute), "{line:?}");
    }
    assert!(picture.contains("gnp·.exe·]52;c;aGk=·"), "{picture}");
    assert!(picture.contains("exa·mple.test"), "{picture}");

    let plain = transcript_with(&fake, &["7"]);
    for line in plain.lines() {
        assert!(!line.chars().any(needs_substitute), "{line:?}");
    }
    assert!(plain.contains("gnp·.exe·]52;c;aGk=·"), "{plain}");
}

fn history_row(process: &str, ip: &str, attempts: u64) -> Value {
    json!({
        "process": process,
        "process-path": "",
        "host": "site.example",
        "remote-ip": ip,
        "route": "secondary",
        "verdict": "permit",
        "blocked-by": "",
        "block-reason": "",
        "first-seen-ms": NOON - 3_600_000,
        "last-seen-ms": NOON,
        "attempts": attempts
    })
}

fn history_service(removed: u64) -> FakeService {
    let fake = service();
    fake.answer(
        IpcOperationName::ConnHistoryList,
        json!({
            "page": {
                "items": [
                    history_row("browser.exe", "203.0.113.70", 12),
                    history_row("mail.exe", "203.0.113.80", 1)
                ],
                "next_cursor": null, "total_count": null, "stale": false
            },
            "enabled": true, "retention-days": 7, "max-retention-days": 30,
            "available": true, "removed": removed, "skipped": 0
        }),
    );
    fake
}

#[test]
fn h_swaps_in_the_kept_history_and_t_walks_its_periods() {
    let fake = history_service(3);
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Trace);
    key(&mut app, KeyCode::Char('h'));
    settle(&mut app, &fake);
    let picture = render(&app, 140, 40);
    assert!(picture.contains("History: Last hour"), "{picture}");
    assert!(picture.contains("Attempts: 12"), "{picture}");
    assert!(
        picture.contains("3 older entries were removed"),
        "{picture}"
    );
    assert!(
        !picture.contains("203.0.113.1:443"),
        "the latest connections are not mixed in:\n{picture}"
    );

    key(&mut app, KeyCode::Char('t'));
    settle(&mut app, &fake);
    assert!(render(&app, 140, 40).contains("History: Today"));
    let sent = fake.sent(IpcOperationName::ConnHistoryList);
    assert_eq!(sent.len(), 2);
    assert_ne!(
        sent[0]["from-unix-ms"], sent[1]["from-unix-ms"],
        "each period asks from its own start"
    );

    key(&mut app, KeyCode::Char('h'));
    settle(&mut app, &fake);
    let picture = render(&app, 140, 40);
    assert!(!picture.contains("History:"), "{picture}");
    assert!(picture.contains("Shown: 12 of 14."), "{picture}");
}

#[test]
fn line_mode_reads_the_history_of_a_period() {
    let fake = history_service(0);
    let text = transcript_with(&fake, &["7", "h week", "d 1"]);
    assert!(text.contains("History: Last 7 days"), "{text}");
    assert!(text.contains("12 times"), "{text}");
    assert_eq!(fake.sent(IpcOperationName::ConnHistoryList).len(), 1);
}

fn path_row(process: &str, path: &str) -> Value {
    let mut row = trace_row(process, "203.0.113.50:443", "primary", "permit", &[]);
    row["process_path"] = json!(path);
    row
}

fn folder_service() -> FakeService {
    let fake = service();
    fake.answer(
        IpcOperationName::ConnTraceEntriesList,
        json!({
            "page": {
                "items": [
                    path_row("avp.exe", r"C:\Program Files\AVP\avp.exe"),
                    path_row("avp2.exe", r"C:\Program Files\AVP\sub\avp2.exe"),
                    path_row("tool.exe", r"C:\Tools\tool.exe"),
                    path_row("svc", ""),
                ],
                "next_cursor": null,
                "total_count": 4,
                "stale": false
            },
            "redacted": false,
            "observer-active": true,
            "gui-stream-enabled": true
        }),
    );
    fake
}

#[test]
fn g_groups_the_trace_by_folder_remembers_it_and_f_fills_the_rule_form() {
    let dir = Scratch::new("trace-grouping");
    let path = dir.path().join("tui.json");
    let fake = folder_service();
    let mut app = connected();
    app.settings.prefs_path = Some(path.clone());
    open(&mut app, &fake, ScreenId::Trace);
    key(&mut app, KeyCode::Tab);
    key(&mut app, KeyCode::Char('g'));
    assert_eq!(app.settings.prefs.trace_grouping, TraceGrouping::Program);
    key(&mut app, KeyCode::Char('g'));
    assert_eq!(app.settings.prefs.trace_grouping, TraceGrouping::Folder);
    assert_eq!(prefs::load(&path).trace_grouping, TraceGrouping::Folder);

    let picture = render(&app, 120, 40);
    assert!(
        picture.contains(r"C:\Program Files\AVP  ·  2 programs  ·  2 connections:"),
        "a folder inside a listed folder joins its group:\n{picture}"
    );
    assert!(
        picture.contains("Programs without a known path"),
        "{picture}"
    );
    assert!(picture.contains("Group: By folder"), "{picture}");
    assert!(picture.contains("Shown: 4 of 4."), "{picture}");
    assert!(picture.contains("f: Rule for this folder…"), "{picture}");
    assert_snapshot("trace-folders-120x40", &picture);

    fake.answer(
        IpcOperationName::RulesList,
        json!({ "rows": [], "supported-rule-types": ["application"] }),
    );
    key(&mut app, KeyCode::Char('f'));
    if !nrr_shared::platform_profile::PlatformProfile::current()
        .supports
        .app_routing
    {
        assert_eq!(app.screen, ScreenId::Trace);
        return;
    }
    assert_eq!(app.screen, ScreenId::Rules);
    // The form waits for the list, so reading it cannot drop the rule.
    settle(&mut app, &fake);
    let value = match &app.rules.mode {
        crate::screens::rules::Mode::Form(form) => form.value.clone(),
        other => panic!("the add form is open, not {other:?}"),
    };
    assert_eq!(value, r"C:\Program Files\AVP\*");
}

/// The add form a rule-from-the-trace key opened, by its value.
fn form_value(app: &AppState) -> String {
    match &app.rules.mode {
        crate::screens::rules::Mode::Form(form) => form.value.clone(),
        other => panic!("the add form is open, not {other:?}"),
    }
}

#[test]
fn i_and_a_fill_the_rule_form_with_the_connections_address_and_program() {
    let fake = service();
    fake.answer(
        IpcOperationName::RulesList,
        json!({ "rows": [], "supported-rule-types": ["exact-ip", "application"] }),
    );
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Trace);
    key(&mut app, KeyCode::Tab);
    key(&mut app, KeyCode::Char('i'));
    assert_eq!(app.screen, ScreenId::Rules);
    settle(&mut app, &fake);
    assert_eq!(
        form_value(&app),
        "203.0.113.1",
        "the port is not part of it"
    );

    if !nrr_shared::platform_profile::PlatformProfile::current()
        .supports
        .app_routing
    {
        return;
    }
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Trace);
    let text = transcript_with(&fake, &["7", "a 2"]);
    assert!(text.contains("Screen: Rules"), "{text}");
    key(&mut app, KeyCode::Tab);
    key(&mut app, KeyCode::Char('a'));
    settle(&mut app, &fake);
    assert_eq!(form_value(&app), "browser.exe");
}

#[test]
fn line_mode_names_a_grouping_and_f_takes_the_folder_of_a_numbered_row() {
    let fake = folder_service();
    let text = transcript_with(&fake, &["7", "g program", "g folder", "f 3"]);
    assert!(text.contains("Group: By program"), "{text}");
    assert!(text.contains("Group: By folder"), "{text}");
    assert!(
        text.contains(r"C:\Tools  ·  1 program  ·  1 connection:"),
        "{text}"
    );
    assert!(text.contains("g: the next grouping"), "{text}");
    if nrr_shared::platform_profile::PlatformProfile::current()
        .supports
        .app_routing
    {
        assert!(text.contains("Screen: Rules"), "{text}");
    }
}

#[test]
fn a_program_seen_once_is_its_row_alone_and_a_header_is_never_explained() {
    let fake = folder_service();
    let mut app = connected();
    app.settings.prefs.trace_grouping = TraceGrouping::Program;
    open(&mut app, &fake, ScreenId::Trace);
    let picture = render(&app, 120, 40);
    assert!(!picture.contains("  ·  1 connection:"), "{picture}");
    assert!(!picture.contains("  ·  2 connections:"), "{picture}");
    assert!(picture.contains("Rows 1–4 of 4."), "{picture}");

    let fake = service();
    let mut app = connected();
    app.settings.prefs.trace_grouping = TraceGrouping::Program;
    open(&mut app, &fake, ScreenId::Trace);
    let picture = render(&app, 120, 40);
    assert!(
        picture.contains("browser.exe  ·  12 connections:"),
        "{picture}"
    );
    key(&mut app, KeyCode::Tab);
    key(&mut app, KeyCode::Enter);
    settle(&mut app, &fake);
    assert_eq!(app.screen, ScreenId::Trace, "a header names no connection");
}

#[test]
fn check_site_from_the_trace_follows_the_check_to_its_verdict() {
    let fake = service();
    fake.answer(
        IpcOperationName::SiteCheckRun,
        json!({ "state": "running", "host": "site.example" }),
    );
    fake.answer(
        IpcOperationName::SiteCheckResultGet,
        json!({
            "state": "done",
            "host": "site.example",
            "report": {
                "site": "site.example",
                "verdict": "sign-in-split",
                "site-route": "secondary",
                "names": [
                    { "name": "site.example", "role": "site", "address": "203.0.113.1",
                      "route": "secondary", "answer": "answered" },
                    { "name": "login.site.example", "role": "sign-in", "address": "203.0.113.7",
                      "route": "primary", "answer": "answered" }
                ],
                "move-names": ["login.site.example"]
            }
        }),
    );
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Trace);
    key(&mut app, KeyCode::Tab);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Char('c'));
    settle(&mut app, &fake);
    assert_eq!(app.screen, ScreenId::Diagnostics);
    assert_eq!(
        fake.sent(IpcOperationName::SiteCheckRun),
        [json!({ "host": "site.example" })]
    );
    // The result is read after a pause, off the jobs thread's queue.
    let later = app.outbox.take_delayed();
    assert_eq!(later.len(), 1, "one read of the running check");
    for (_, job) in later {
        (job(&fake).0)(&mut app);
    }
    let text: Vec<String> = super::site_check::lines(&app, &texts_en(), None)
        .iter()
        .map(|l| l.plain_text())
        .collect();
    let text = text.join("\n");
    assert!(
        text.contains("The site's sign-in goes over a different route than the site"),
        "{text}"
    );
    assert!(text.contains("login.site.example (sign-in)"), "{text}");
    assert!(text.contains("m: move the sign-in names"), "{text}");
    assert!(
        app.outbox.take_delayed().is_empty(),
        "a finished check is not read again"
    );
}

/// Diagnostics after a check of `site.example` that ended in `verdict`.
fn checked_site(verdict: &str) -> (AppState, FakeService) {
    let fake = service();
    fake.answer(
        IpcOperationName::SiteCheckRun,
        json!({ "state": "running", "host": "site.example" }),
    );
    fake.answer(
        IpcOperationName::SiteCheckResultGet,
        json!({
            "state": "done",
            "host": "site.example",
            "report": {
                "site": "site.example",
                "verdict": verdict,
                "site-route": "primary",
                "names": [
                    { "name": "site.example", "role": "site", "address": "203.0.113.1",
                      "route": "primary", "answer": "silent" }
                ]
            }
        }),
    );
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Diagnostics);
    super::diagnostics::check_site(&mut app, "site.example");
    settle(&mut app, &fake);
    for (_, job) in app.outbox.take_delayed() {
        (job(&fake).0)(&mut app);
    }
    (app, fake)
}

/// A site that does not answer over its route leads on to the trace, where
/// its connections show what happened; a verdict that does not, does not.
#[test]
fn a_site_that_does_not_answer_leads_on_to_the_trace() {
    for verdict in ["not-answering", "route-down"] {
        let (mut app, _fake) = checked_site(verdict);
        let text: Vec<String> = super::site_check::lines(&app, &texts_en(), None)
            .iter()
            .map(|l| l.plain_text())
            .collect();
        assert!(
            text.iter()
                .any(|l| l.starts_with("t: open the connection trace")),
            "{verdict}: {text:?}"
        );
        key(&mut app, KeyCode::Char('t'));
        assert_eq!(app.screen, ScreenId::Trace, "{verdict}");
    }
    let (mut app, _fake) = checked_site("fine");
    key(&mut app, KeyCode::Char('t'));
    assert_eq!(
        app.screen,
        ScreenId::Diagnostics,
        "a fine site has no trace step"
    );
}

fn diagnostics_with_tamper(card: Value) -> String {
    let fake = service();
    let mut status = diagnostics_status();
    status["dns_tamper"] = card;
    fake.answer(
        IpcOperationName::SnapshotDiagnosticsGet,
        json!({ "status": status }),
    );
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Diagnostics);
    render(&app, 200, 60)
}

#[test]
fn the_dns_tampering_card_shows_only_when_sites_were_affected() {
    let quiet = diagnostics_with_tamper(json!({ "affected_hosts": 0, "examples": [] }));
    assert!(!quiet.contains("changes some DNS answers"), "{quiet}");

    let counted = diagnostics_with_tamper(json!({ "affected_hosts": 3, "examples": [] }));
    assert!(
        counted.contains("Your provider changes some DNS answers"),
        "{counted}"
    );
    assert!(counted.contains("For 3 sites"), "{counted}");
    assert!(!counted.contains("For example"), "{counted}");

    let named = diagnostics_with_tamper(
        json!({ "affected_hosts": 2, "examples": ["a.example", "b.example"] }),
    );
    assert!(
        named.contains("For example: a.example, b.example"),
        "{named}"
    );
}

#[test]
fn a_tampered_name_is_cleaned_before_it_reaches_the_terminal() {
    use nrr_shared::display_text::needs_substitute;
    let picture = diagnostics_with_tamper(
        json!({ "affected_hosts": 1, "examples": ["evil\u{202E}.example\u{1b}]0;x\u{7}"] }),
    );
    assert!(picture.contains("For example: evil"), "{picture}");
    // The rows are joined by newlines; only the tampered text must be clean.
    assert!(
        !picture.chars().any(|c| c != '\n' && needs_substitute(c)),
        "{picture}"
    );
}

#[test]
fn a_health_warning_from_the_service_is_listed_and_a_clean_one_is_not() {
    use nrr_shared::ipc_payloads::{HealthComponentResponse, ServiceHealthResponse};
    let component = |severity: &str, message: Option<&str>| HealthComponentResponse {
        component: "crash-recovery".into(),
        severity: severity.into(),
        message: message.map(str::to_owned),
    };
    let health = |components| ServiceHealthResponse {
        service_state: "degraded".into(),
        worst_severity: "warning".into(),
        active_revision_id: None,
        components,
        fake_ip_datapath: None,
    };
    let warned = super::diagnostics::health_warning_lines(&health(vec![
        component(
            "warning",
            Some("started again after the service was stopped by something other than this program; protection was off in between"),
        ),
        component("ok", Some("fine")),
        component("warning", None),
    ]));
    assert_eq!(warned.len(), 1);
    assert!(warned[0].segments[0].text.contains("protection was off"));
    assert!(super::diagnostics::health_warning_lines(&health(Vec::new())).is_empty());
}

/// The archive is exported with the options on screen: standard detail and
/// this session's logs from its local midnight unless the user changes them,
/// and the log size limit only once one is picked.
#[test]
fn the_archive_is_exported_with_the_options_chosen() {
    let fake = service();
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Diagnostics);
    let text = view_text(&app, ScreenId::Diagnostics);
    assert!(
        text.contains("Detail level: Standard (recommended)"),
        "{text}"
    );
    assert!(
        text.contains("Only logs from the current session: Yes"),
        "{text}"
    );
    assert!(
        text.contains("Log size limit in the archive: Unlimited"),
        "{text}"
    );

    key(&mut app, KeyCode::Char('x'));
    settle(&mut app, &fake);
    let sent = fake.sent(IpcOperationName::DiagnosticsExportArchive);
    assert_eq!(sent[0]["redaction-level"], json!("standard"), "{sent:?}");
    assert!(sent[0].get("raw-log-budget-bytes").is_none(), "{sent:?}");
    let session_start = app.inspect.diag.session_start_ms;
    let from = sent[0]["logs-from-ms"]
        .as_i64()
        .expect("this session's logs");
    assert!(
        from <= session_start && session_start - from < 86_400_000 + 3_600_000,
        "{from} for a session that started at {session_start}"
    );

    key(&mut app, KeyCode::Char('d'));
    key(&mut app, KeyCode::Char('o'));
    key(&mut app, KeyCode::Char('b'));
    let text = view_text(&app, ScreenId::Diagnostics);
    assert!(text.contains("Detail level: Full diagnostics"), "{text}");
    assert!(
        text.contains("Only logs from the current session: No"),
        "{text}"
    );
    assert!(
        text.contains("Log size limit in the archive: 24 MiB"),
        "{text}"
    );
    key(&mut app, KeyCode::Char('x'));
    settle(&mut app, &fake);
    let sent = fake.sent(IpcOperationName::DiagnosticsExportArchive);
    assert_eq!(sent[1]["redaction-level"], json!("diagnostics"), "{sent:?}");
    assert!(
        sent[1]["logs-from-ms"].is_null(),
        "the whole history: {sent:?}"
    );
    assert_eq!(
        sent[1]["raw-log-budget-bytes"],
        json!(24 * 1024 * 1024),
        "{sent:?}"
    );
}

/// The category typed is the one the service is asked to keep, and clearing
/// it asks for every category again.
#[test]
fn a_log_category_filter_asks_only_for_that_category() {
    let fake = service();
    transcript_with(&fake, &["9", "l", "c service", "c"]);
    let sent = fake.sent(IpcOperationName::LogsList);
    let categories: Vec<&serde_json::Value> =
        sent.iter().map(|s| &s["filter"]["category"]).collect();
    assert_eq!(
        categories,
        [&json!(null), &json!("service"), &json!(null)],
        "{sent:?}"
    );
}

/// The log reads newest first; another column orders the rows by it, and a
/// reversal turns that order round, as the window's header clicks do.
#[test]
fn the_log_and_the_audit_trail_sort_by_the_column_chosen() {
    let fake = service();
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Diagnostics);
    key(&mut app, KeyCode::Char('l'));
    settle(&mut app, &fake);
    let order = |app: &AppState| {
        let text = view_text(app, ScreenId::Diagnostics);
        let dns = text.find("DNS refresh").expect("dns row");
        let slow = text.find("Apply took long").expect("slow row");
        (dns < slow, text)
    };
    let (dns_first, text) = order(&app);
    assert!(dns_first, "newest first: {text}");
    assert!(text.contains("Sorted by Time, descending"), "{text}");

    key(&mut app, KeyCode::Char('o'));
    let (dns_first, text) = order(&app);
    assert!(text.contains("Sorted by Level, ascending"), "{text}");
    assert!(dns_first, "info before warn: {text}");
    key(&mut app, KeyCode::Char('d'));
    let (dns_first, text) = order(&app);
    assert!(!dns_first, "warn before info: {text}");

    key(&mut app, KeyCode::Char('l'));
    settle(&mut app, &fake);
    let text = view_text(&app, ScreenId::Diagnostics);
    assert!(text.contains("Sorted by Seq, descending"), "{text}");
    assert!(
        text.find("#8").expect("seq 8") < text.find("#7").expect("seq 7"),
        "{text}"
    );
    key(&mut app, KeyCode::Char('d'));
    let text = view_text(&app, ScreenId::Diagnostics);
    assert!(
        text.find("#7").expect("seq 7") < text.find("#8").expect("seq 8"),
        "{text}"
    );
}

/// Which logs and how much the archive takes outlive the run; a raised detail
/// level does not, so a later archive never carries more than standard detail
/// unless asked for again.
#[test]
fn archive_options_are_kept_but_the_detail_level_starts_standard_again() {
    let dir = crate::testing::Scratch::new("archive-options-kept");
    let path = dir.path().join("tui.json");
    let fake = service();
    let mut app = connected();
    app.settings.prefs_path = Some(path.clone());
    open(&mut app, &fake, ScreenId::Diagnostics);
    key(&mut app, KeyCode::Char('d'));
    key(&mut app, KeyCode::Char('o'));
    key(&mut app, KeyCode::Char('b'));

    let mut next = connected();
    next.settings.prefs = crate::screens::settings::prefs::load(&path);
    crate::screens::inspect::diagnostics::restore_archive_options(&mut next);
    open(&mut next, &fake, ScreenId::Diagnostics);
    let text = view_text(&next, ScreenId::Diagnostics);
    assert!(
        text.contains("Detail level: Standard (recommended)"),
        "{text}"
    );
    assert!(
        text.contains("Only logs from the current session: No"),
        "{text}"
    );
    assert!(
        text.contains("Log size limit in the archive: 24 MiB"),
        "{text}"
    );
}
