#![allow(clippy::expect_used)]

use std::cell::Cell;
use std::time::Instant;

use nrr_client_logic::site_notice::SITE_NOTICE_GAP_MS;
use nrr_ipc_client::ConnectionStatus;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::StatusUpdateEvent;
use serde_json::json;

use super::*;
use crate::backend::{BackendEvent, PushEvent};
use crate::link::Link;
use crate::screens::settings::Clock;
use crate::screens::suggestions::tests::drain;
use crate::testing::{app_at, texts_en, FakeService, Fixture, Scratch};

const T0: i64 = 1_800_000_000_000;
const HOUR: i64 = 60 * 60 * 1000;
const DAY: i64 = 24 * HOUR;

#[test]
fn another_sites_notice_does_not_hide_a_newly_confirmed_site_for_minutes() {
    let mut log = SiteNoticeLog::default();
    log.told("already-shown.example", T0);
    assert!(
        log.due("new-failure.example", false, T0 + 60_000),
        "the terminal must offer a new confirmed host promptly too"
    );
    assert!(log.due("already-shown.example", false, T0 + 60_000));
    assert!(!log.due("new-failure.example", true, T0 + 60_000));
}

#[test]
fn a_burst_of_sites_shares_the_short_batch_window() {
    let mut log = SiteNoticeLog::default();
    assert!(log.due("one.example", false, T0));
    log.told("one.example", T0);
    assert!(!log.due("two.example", false, T0 + SITE_NOTICE_GAP_MS - 1));
    assert!(log.due("two.example", false, T0 + SITE_NOTICE_GAP_MS));
    assert!(
        !log.due("two.example", true, T0 + DAY),
        "muted is never told"
    );
}

#[test]
fn the_same_unanswered_site_is_eligible_within_twenty_seconds() {
    let mut log = SiteNoticeLog::default();
    log.told("site.example", T0);
    assert!(!log.due("site.example", false, T0 + 14_999));
    assert!(log.due("site.example", false, T0 + 15_000));
    assert!(log.due("site.example", false, T0 + 20_000));
    assert!(!log.due("site.example", true, T0 + 20_000));
    log.told("site.example", T0 + 20_000);
    assert!(!log.due("site.example", false, T0 + 20_001));
}

#[test]
fn the_log_reads_back_and_the_settings_save_keeps_it() {
    let scratch = Scratch::new("site-notices");
    let path = scratch.path().join("tui.json");
    let mut app = AppState::new(crate::screens::ScreenId::Status, false);
    app.settings.prefs_path = Some(path.clone());
    app.site_notices.told("site.example", T0);
    save(&mut app);
    // The Settings screen writes the same file afterwards.
    prefs::save(&path, app.settings.prefs).expect("prefs saved");
    assert_eq!(load(&path), app.site_notices);
    assert!(!load(&path).due("site.example", false, T0 + 10_000));
    assert!(load(&path).due("site.example", false, T0 + 20_000));
}

/// The file is anybody's to break: whatever it holds, reading it never
/// panics, never keeps more than the cap, and never holds a notice back for
/// longer than the rule does.
#[test]
fn a_broken_or_hostile_file_never_silences_the_notice_for_good() {
    let scratch = Scratch::new("site-notices-hostile");
    let path = scratch.path().join("tui.json");
    for body in [
        "{ not json".to_owned(),
        json!({ "site-notices": "everything" }).to_string(),
        json!({ "site-notices": { "shown": "soon", "shown:site.example": [1] } }).to_string(),
        json!({ "site-notices": { "shown": i64::MAX, "shown:site.example": i64::MAX } })
            .to_string(),
        json!({ "site-notices": { "shown:\u{7}bell.example": T0 } }).to_string(),
        format!(
            "{{\"site-notices\": {{\"shown\": {T0}}}, \"pad\": \"{}\"}}",
            "x".repeat(2 << 20)
        ),
    ] {
        std::fs::write(&path, &body).expect("write");
        let log = load(&path);
        assert!(
            log.due("site.example", false, T0 + 1),
            "held back by {:.80}",
            body
        );
    }
    let many: serde_json::Map<String, Value> = (0..5000)
        .map(|i| (format!("shown:s{i}.example"), Value::from(T0 + i)))
        .collect();
    std::fs::write(&path, json!({ "site-notices": many }).to_string()).expect("write");
    let log = load(&path);
    assert_eq!(log.sites.len(), MAX_SITES);
    assert!(
        log.sites.contains_key("s4999.example"),
        "the newest are kept"
    );
}

// ── The feed ─────────────────────────────────────────────────────────────────

thread_local! {
    static NOW: Cell<i64> = const { Cell::new(T0) };
}

fn now() -> i64 {
    NOW.with(Cell::get)
}

fn set_now(at: i64) {
    NOW.with(|n| n.set(at));
}

fn blocked(host: &str) -> serde_json::Value {
    json!({
        "id": format!("id-{host}"), "anchor": host, "proposed-match": host,
        "match-kind": "suffix", "route": "secondary", "affinity": 0.0,
        "first-seen-unix-ms": 1000, "last-seen-unix-ms": 1000,
        "signal": "main-link-blocked", "primary-behavior": "stalls"
    })
}

fn service(hosts: &[&str]) -> FakeService {
    let fake = FakeService::new(ConnectionStatus::Connected);
    fake.answer(
        IpcOperationName::AutoRuleCandidatesList,
        json!({
            "candidates": hosts.iter().map(|h| blocked(h)).collect::<Vec<_>>(),
            "pending-count": hosts.len(), "inert-dropped": 0, "inert-sample": []
        }),
    );
    fake.answer(
        IpcOperationName::AutoRuleDismissedList,
        json!({ "dismissed": [] }),
    );
    fake.answer(
        IpcOperationName::AutoRuleCandidatesAccept,
        json!({ "applied": 1, "unknown": 0, "pending": 0, "anchor-skipped": false }),
    );
    fake.answer(
        IpcOperationName::AutoRuleCandidatesDismiss,
        json!({ "applied": 1, "unknown": 0, "pending": 0 }),
    );
    fake
}

fn pushed(app: &mut AppState, fake: &FakeService, host: &str) -> usize {
    let before = app.notices.len();
    app.apply(
        BackendEvent::Push(PushEvent::Status(Box::new(
            StatusUpdateEvent::AutoRuleCandidatesChanged {
                sid: "S".into(),
                pending_count: 1,
                top_anchor: host.into(),
                announces: true,
            },
        ))),
        &texts_en(),
        Instant::now(),
    );
    drain(app, fake);
    app.notices.len() - before
}

fn on_status(fake: &FakeService) -> AppState {
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    app.settings.clock = Clock {
        now_ms: now,
        utc_offset: |_| 0,
    };
    drain(&mut app, fake);
    app
}

#[test]
fn a_paced_ready_site_is_retried_without_another_service_push() {
    set_now(T0);
    let fake = service(&["himalayas.app"]);
    let mut app = on_status(&fake);
    app.site_notices.told("himalayas.app", T0);
    set_now(T0 + 1);
    assert_eq!(pushed(&mut app, &fake, "himalayas.app"), 0);
    set_now(T0 + 15_001);
    assert!(crate::screens::suggestions::retry_paced_notice(&mut app));
    drain(&mut app, &fake);
    assert!(app
        .notices
        .iter()
        .any(|notice| notice.body.contains("himalayas.app")));
    assert!(!crate::screens::suggestions::retry_paced_notice(&mut app));
}

#[test]
fn a_pacing_retry_cannot_resurrect_a_withdrawn_site_offer() {
    set_now(T0);
    let fake = service(&["himalayas.app"]);
    let mut app = on_status(&fake);
    app.site_notices.told("himalayas.app", T0);
    set_now(T0 + 1);
    assert_eq!(pushed(&mut app, &fake, "himalayas.app"), 0);
    fake.answer(
        IpcOperationName::AutoRuleCandidatesList,
        json!({"candidates": [], "pending-count": 0, "inert-dropped": 0, "inert-sample": []}),
    );
    set_now(T0 + 15_001);
    assert!(crate::screens::suggestions::retry_paced_notice(&mut app));
    drain(&mut app, &fake);
    assert!(
        app.notices.is_empty(),
        "a fresh list no longer offers the site"
    );
}

#[test]
fn a_known_top_anchor_cannot_hide_a_newly_confirmed_name_in_the_same_batch() {
    set_now(T0);
    let fake = service(&["one.example"]);
    let mut app = on_status(&fake);
    assert_eq!(pushed(&mut app, &fake, "one.example"), 1);
    set_now(T0 + 60_000);
    fake.answer(
        IpcOperationName::AutoRuleCandidatesList,
        json!({
            "candidates": [blocked("one.example"), blocked("new.example")],
            "pending-count": 2, "inert-dropped": 0, "inert-sample": []
        }),
    );
    assert_eq!(pushed(&mut app, &fake, "one.example"), 0);
    assert!(
        app.notices
            .last()
            .expect("updated batch")
            .body
            .contains("new.example"),
        "the old top anchor must not silence a new actual host after the list reloads"
    );
}

#[test]
fn successive_confirmed_sites_update_one_feed_notice_instead_of_stacking_cards() {
    set_now(T0);
    let fake = service(&["one.example"]);
    let mut app = on_status(&fake);
    assert_eq!(pushed(&mut app, &fake, "one.example"), 1);
    let original_id = app.notices.last().expect("first card").id;
    set_now(T0 + HOUR);
    fake.answer(
        IpcOperationName::AutoRuleCandidatesList,
        json!({
            "candidates": [blocked("one.example"), blocked("two.example")],
            "pending-count": 2, "inert-dropped": 0, "inert-sample": []
        }),
    );
    assert_eq!(
        pushed(&mut app, &fake, "two.example"),
        0,
        "the existing batch is updated in place"
    );
    let card = app.notices.last().expect("updated card");
    assert_eq!(
        card.id, original_id,
        "new names must not move the user's feed selection"
    );
    assert!(card.body.contains("one.example") && card.body.contains("two.example"));
}

/// New names share one feed card; an unanswered name is not repeated.
#[test]
fn the_feed_tells_of_sites_that_do_not_open_as_the_tray_does() {
    set_now(T0);
    let fake = service(&["one.example", "two.example"]);
    let mut app = on_status(&fake);
    assert_eq!(pushed(&mut app, &fake, "one.example"), 1, "first told");
    set_now(T0 + 60_000);
    assert_eq!(
        pushed(&mut app, &fake, "two.example"),
        0,
        "already included in the first batch"
    );
    set_now(T0 + HOUR);
    assert_eq!(
        pushed(&mut app, &fake, "one.example"),
        0,
        "the same site, same day"
    );
    assert_eq!(
        pushed(&mut app, &fake, "two.example"),
        0,
        "a site already shown in the batch still waits its own day"
    );

    // Added from Suggestions: one.example's notice was answered.
    app.outbox
        .push(crate::screens::suggestions::accept_job_for_tests(vec![
            "id-one.example".into(),
        ]));
    drain(&mut app, &fake);
    set_now(T0 + 2 * HOUR);
    assert_eq!(
        pushed(&mut app, &fake, "one.example"),
        0,
        "an answered site returns to the existing feed batch"
    );
    assert_eq!(
        app.site_notices.sites["one.example"].shown,
        Some(T0 + 2 * HOUR)
    );
}

/// "Never suggest" is an answer too, as the tray counts it: the site's day
/// no longer holds its notice back.
#[test]
fn never_suggest_answers_the_notice_as_the_tray_counts_it() {
    set_now(T0);
    let fake = service(&["one.example"]);
    let mut app = on_status(&fake);
    assert_eq!(pushed(&mut app, &fake, "one.example"), 1, "first told");
    app.outbox
        .push(crate::screens::suggestions::dismiss_job_for_tests(vec![
            "id-one.example".into(),
        ]));
    drain(&mut app, &fake);
    set_now(T0 + HOUR);
    assert_eq!(
        pushed(&mut app, &fake, "one.example"),
        0,
        "an answered notice updates the existing feed batch"
    );
    assert_eq!(app.site_notices.sites["one.example"].shown, Some(T0 + HOUR));
}
