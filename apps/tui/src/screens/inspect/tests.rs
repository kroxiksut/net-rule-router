#![allow(clippy::expect_used)]

//! The trace, cache and diagnostics screens on the scripted service: full
//! screen snapshots, line-mode transcripts, and the operations each action
//! sends.

use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use nrr_ipc_client::{ConnectionStatus, IpcClient};
use nrr_shared::ipc::IpcOperationName;
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use serde_json::{json, Value};

use crate::full::{draw, handle_key, RenderOptions};
use crate::link::Link;
use crate::plain::PlainSession;
use crate::screens::ScreenId;
use crate::state::AppState;
use crate::testing::{app_at, assert_snapshot, texts_en, FakeService, Fixture};

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

/// A service with an answer for every operation the three screens use.
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
                "components": [], "degraded-modes": [] }),
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
        IpcOperationName::DiagnosticsExportArchive,
        json!({ "archive-path": "/nonexistent/archives/nrr-diag.zip", "size-bytes": 2048,
                "generated-at-ms": NOON }),
    );
    fake
}

fn connected() -> AppState {
    app_at(Link::Connected, Some(&Fixture::healthy()))
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

#[test]
fn an_alert_that_trusts_rule_sets_shows_them_before_acknowledging() {
    let fake = service();
    let mut app = connected();
    open(&mut app, &fake, ScreenId::Diagnostics);
    assert_snapshot("diagnostics-100x40", &render(&app, 100, 40));

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

/// Line mode: the screen, its commands, a page at a time.
fn transcript(answers: &[&str]) -> String {
    let fake = service();
    let texts = texts_en();
    let mut app = connected();
    let mut session = PlainSession::new(Vec::new());
    session.start(&app, &texts).expect("start");
    for answer in answers {
        session.input(answer, &mut app, &texts).expect("answer");
        settle(&mut app, &fake);
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
