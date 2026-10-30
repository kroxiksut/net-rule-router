#![allow(clippy::expect_used)]

use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use nrr_ipc_client::ConnectionStatus;
use nrr_shared::ipc_payloads::StatusUpdateEvent;
use serde_json::json;

use super::*;
use crate::backend::{BackendEvent, PushEvent};
use crate::link::Link;
use crate::screens::screen;
use crate::screens::settings::Clock;
use crate::testing::{app_at, missing_from_locales, texts_en, FakeService, Fixture, Scratch};

const SITE: &str = "news.example";
/// The instant every test's clock reads.
const NOW_MS: i64 = 1_800_000_000_000;

fn fixed_clock() -> Clock {
    Clock {
        now_ms: || NOW_MS,
        utc_offset: |_| 0,
    }
}

fn push(event: StatusUpdateEvent) -> BackendEvent {
    BackendEvent::Push(PushEvent::Status(Box::new(event)))
}

fn blocked(destination: &str, app: &str, reason: &str) -> BackendEvent {
    push(StatusUpdateEvent::BlockNoticeRaised {
        sid: "S".into(),
        destination: destination.into(),
        app: app.into(),
        reason: reason.into(),
        attempts: 2,
        launched_by: Vec::new(),
    })
}

fn tunnel_found() -> BackendEvent {
    push(StatusUpdateEvent::UnassignedTunnelDetected {
        sid: "S".into(),
        adapter_name: "Example Tunnel".into(),
    })
}

/// The Status screen, connected, on a fixed clock, with nothing queued.
fn on_status() -> AppState {
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    app.settings.clock = fixed_clock();
    app.outbox.take();
    app
}

fn arrive(app: &mut AppState, event: BackendEvent) {
    app.apply(event, &texts_en(), Instant::now());
}

fn press(app: &mut AppState, code: KeyCode) {
    let modifiers = if matches!(code, KeyCode::Char(c) if c.is_ascii_uppercase()) {
        KeyModifiers::SHIFT
    } else {
        KeyModifiers::NONE
    };
    crate::full::handle_key(app, KeyEvent::new(code, modifiers), &texts_en());
}

fn to_feed(app: &mut AppState) {
    press(app, KeyCode::Tab);
    assert_eq!(app.focus, Focus::Feed);
}

fn drain(app: &mut AppState, service: &FakeService) {
    let texts = texts_en();
    for _ in 0..10 {
        let jobs = app.outbox.take();
        if jobs.is_empty() {
            return;
        }
        for job in jobs {
            let reply = job(service as &dyn IpcClient);
            app.apply(BackendEvent::Reply(reply), &texts, Instant::now());
        }
    }
    panic!("jobs keep queueing more jobs");
}

fn feed_text(app: &AppState) -> String {
    lines(app, &texts_en())
        .iter()
        .map(|l| l.plain_text() + "\n")
        .collect()
}

/// The service that accepts a mute and answers with `mutes`.
fn muting_service(mutes: serde_json::Value) -> FakeService {
    let fake = FakeService::new(ConnectionStatus::Connected);
    fake.answer(
        IpcOperationName::BlockNoticeMutesSet,
        json!({ "mutes": mutes }),
    );
    fake
}

fn titles(app: &AppState) -> Vec<String> {
    app.notices.iter().map(|n| n.title.clone()).collect()
}

#[test]
fn every_key_is_in_both_locale_files() {
    let missing = missing_from_locales(&keys());
    assert!(missing.is_empty(), "{missing:?}");
}

/// The chosen notice goes and the choice stays where it was; "dismiss all"
/// leaves nothing behind.
#[test]
fn dismiss_takes_the_chosen_notice_and_dismiss_all_empties_the_feed() {
    let mut app = on_status();
    arrive(&mut app, blocked("old.example", "", "blocked-by-rule"));
    arrive(&mut app, blocked("mid.example", "", "blocked-by-rule"));
    arrive(&mut app, tunnel_found());
    to_feed(&mut app);
    press(&mut app, KeyCode::Down);
    assert!(
        feed_text(&app).contains("> 2. Warning: Connection blocked"),
        "{}",
        feed_text(&app)
    );

    press(&mut app, KeyCode::Char('x'));

    assert_eq!(app.notices.iter().map(|n| n.id).collect::<Vec<_>>(), [1, 3]);
    assert!(feed_text(&app).contains("> 1. "), "{}", feed_text(&app));
    assert_eq!(app.screen, ScreenId::Status, "x is not a screen key here");

    press(&mut app, KeyCode::Char('X'));
    assert!(app.notices.is_empty());
    assert!(feed_text(&app).contains("No notifications."));
}

/// A notice that arrives does not move the choice off the one being read.
#[test]
fn the_choice_stays_on_its_notice_when_a_newer_one_arrives() {
    let mut app = on_status();
    arrive(&mut app, blocked("a.example", "", "blocked-by-rule"));
    arrive(&mut app, blocked("b.example", "", "blocked-by-rule"));
    to_feed(&mut app);
    press(&mut app, KeyCode::Down);
    arrive(&mut app, tunnel_found());
    press(&mut app, KeyCode::Char('x'));
    assert!(
        app.notices.iter().all(|n| n.id != 1),
        "the older block was chosen: {:?}",
        app.notices
    );
    assert_eq!(app.notices.len(), 2);
}

/// "Don't show…" on a kind: the service is told for how long, the notice
/// leaves the feed, and the next one of that kind stays out.
#[test]
fn a_hidden_kind_leaves_the_feed_and_its_next_notice_stays_out() {
    let fake = muting_service(json!([
        { "scope": { "kind": "notice", "notice": "unassigned-tunnel" },
          "until-unix-ms": NOW_MS + 24 * 60 * 60 * 1000 }
    ]));
    let mut app = on_status();
    arrive(&mut app, tunnel_found());
    to_feed(&mut app);
    press(&mut app, KeyCode::Char('m'));
    let asked = feed_text(&app);
    assert!(asked.contains("Stop showing this notification?"), "{asked}");
    assert!(asked.contains("1: For a day"), "{asked}");

    press(&mut app, KeyCode::Char('1'));
    drain(&mut app, &fake);

    assert_eq!(
        fake.sent(IpcOperationName::BlockNoticeMutesSet),
        vec![json!({
            "scope": { "kind": "notice", "notice": "unassigned-tunnel" },
            "until-unix-ms": NOW_MS + 24 * 60 * 60 * 1000
        })]
    );
    assert_eq!(app.screen, ScreenId::Status, "the digit was an answer");
    assert!(app.notices.is_empty(), "{:?}", app.notices);
    arrive(&mut app, tunnel_found());
    assert!(app.notices.is_empty(), "{:?}", app.notices);
}

/// A kind silenced on another surface takes its notices out of the feed
/// when the change is read, as the window's cards go.
#[test]
fn a_kind_muted_elsewhere_takes_its_notices_out_of_the_feed() {
    let fake = FakeService::new(ConnectionStatus::Connected);
    fake.answer(
        IpcOperationName::BlockNoticeMutesList,
        json!({ "mutes": [{ "scope": { "kind": "notice", "notice": "unassigned-tunnel" } }] }),
    );
    let mut app = on_status();
    arrive(&mut app, tunnel_found());
    arrive(&mut app, blocked(SITE, "", "blocked-by-rule"));
    arrive(
        &mut app,
        push(StatusUpdateEvent::BlockNoticeMutesChanged { sid: "S".into() }),
    );
    drain(&mut app, &fake);
    assert_eq!(titles(&app), ["Connection blocked"]);
}

/// Hiding addresses keeps the destination out of every text the feed shows,
/// yet the mute still names the host the service matches.
#[test]
fn a_hidden_address_is_never_shown_but_the_mute_names_the_real_host() {
    let fake = muting_service(json!([]));
    let mut app = on_status();
    app.settings.prefs.hide_block_addresses = true;
    arrive(&mut app, blocked(SITE, "browser.exe", "blocked-by-rule"));
    to_feed(&mut app);
    press(&mut app, KeyCode::Char('m'));

    let shown = feed_text(&app);
    assert!(!shown.contains(SITE), "{shown}");
    assert!(shown.contains("a hidden destination"), "{shown}");
    assert!(shown.contains("1: Only a hidden destination"), "{shown}");
    assert!(shown.contains("2: All from browser.exe"), "{shown}");
    assert!(shown.contains("3: All \"Denied by rules\""), "{shown}");
    assert!(shown.contains("4: All blocks"), "{shown}");
    let plain = crate::plain::notice_line(&app.notices[0], hide_addresses(&app), &texts_en());
    assert!(!plain.contains(SITE), "{plain}");
    assert!(
        plain.starts_with("1. Warning: Connection blocked"),
        "{plain}"
    );

    press(&mut app, KeyCode::Char('1'));
    drain(&mut app, &fake);
    assert_eq!(
        fake.sent(IpcOperationName::BlockNoticeMutesSet),
        vec![json!({ "scope": { "kind": "host", "host": SITE } })]
    );
    assert!(app.notices.is_empty(), "the answered notice goes");
}

/// Each block scope writes its own mute: the program, the reason, or all.
#[test]
fn a_block_is_muted_by_program_by_reason_or_whole() {
    for (answer, scope) in [
        ('2', json!({ "kind": "app", "app": "browser.exe" })),
        (
            '3',
            json!({ "kind": "reason", "reason": "blocked-by-rule" }),
        ),
        ('4', json!({ "kind": "all" })),
    ] {
        let fake = muting_service(json!([]));
        let mut app = on_status();
        arrive(&mut app, blocked(SITE, "browser.exe", "blocked-by-rule"));
        to_feed(&mut app);
        press(&mut app, KeyCode::Char('m'));
        press(&mut app, KeyCode::Char(answer));
        drain(&mut app, &fake);
        assert_eq!(
            fake.sent(IpcOperationName::BlockNoticeMutesSet),
            vec![json!({ "scope": scope })],
            "{answer}"
        );
    }
}

/// An unattributed block offers no "all from this program": there is none.
#[test]
fn a_block_without_a_program_offers_no_program_scope() {
    let mut app = on_status();
    arrive(&mut app, blocked(SITE, "", "blocked-by-rule"));
    to_feed(&mut app);
    press(&mut app, KeyCode::Char('m'));
    let shown = feed_text(&app);
    assert!(!shown.contains("All from"), "{shown}");
    assert!(shown.contains("2: All \"Denied by rules\""), "{shown}");
}

/// Snooze lasts as long as chosen by the app's clock, never longer: the
/// deadline goes to the service, which lifts it then.
#[test]
fn a_snooze_holds_the_host_until_the_chosen_time() {
    for (answer, span) in [('1', 15 * 60 * 1000), ('6', 30 * 24 * 60 * 60 * 1000)] {
        let fake = muting_service(json!([]));
        let mut app = on_status();
        arrive(&mut app, blocked(SITE, "browser.exe", "blocked-by-rule"));
        to_feed(&mut app);
        press(&mut app, KeyCode::Char('s'));
        assert!(
            feed_text(&app).contains("Stop asking about news.example for a while."),
            "{}",
            feed_text(&app)
        );
        press(&mut app, KeyCode::Char(answer));
        drain(&mut app, &fake);
        assert_eq!(
            fake.sent(IpcOperationName::BlockNoticeMutesSet),
            vec![json!({
                "scope": { "kind": "host", "host": SITE },
                "until-unix-ms": NOW_MS + span
            })],
            "{answer}"
        );
    }
}

/// Esc or n closes a question without writing anything.
#[test]
fn a_cancelled_question_writes_nothing() {
    for cancel in [KeyCode::Esc, KeyCode::Char('n')] {
        let fake = muting_service(json!([]));
        let mut app = on_status();
        arrive(&mut app, blocked(SITE, "", "blocked-by-rule"));
        to_feed(&mut app);
        press(&mut app, KeyCode::Char('s'));
        press(&mut app, cancel);
        drain(&mut app, &fake);
        assert!(fake.operations().is_empty(), "{cancel:?}");
        assert!(!question_open(&app));
        assert_eq!(app.notices.len(), 1);
    }
}

/// A mute the service refuses is said, and the notice stays to try again.
#[test]
fn a_refused_mute_is_a_warning_and_the_notice_stays() {
    let fake = FakeService::new(ConnectionStatus::Connected);
    let mut app = on_status();
    arrive(&mut app, blocked(SITE, "", "blocked-by-rule"));
    to_feed(&mut app);
    press(&mut app, KeyCode::Char('m'));
    press(&mut app, KeyCode::Char('1'));
    drain(&mut app, &fake);
    let last = app.notices.last().expect("a notice");
    assert_eq!(last.level, NoticeLevel::Warning);
    assert!(
        last.body.starts_with("Could not add the mute: "),
        "{}",
        last.body
    );
    assert!(app.notices.iter().any(|n| n.id == 1), "{:?}", app.notices);
}

/// "Why?" runs the explain probe for the blocked host in Diagnostics.
#[test]
fn why_explains_the_blocked_host() {
    let mut app = on_status();
    arrive(&mut app, blocked(SITE, "browser.exe", "route-unavailable"));
    to_feed(&mut app);
    press(&mut app, KeyCode::Char('w'));
    assert_eq!(app.screen, ScreenId::Diagnostics);
    let fake = FakeService::new(ConnectionStatus::Connected);
    drain(&mut app, &fake);
    let sent = fake.sent(IpcOperationName::ExplainGet);
    assert_eq!(sent.len(), 1, "{:?}", fake.operations());
    assert!(sent[0].to_string().contains(SITE), "{}", sent[0]);
}

fn silent_on_both_links(host: &str) -> BackendEvent {
    push(StatusUpdateEvent::HostUnreachableOnBothRoutes {
        sid: "S".into(),
        host: host.into(),
    })
}

/// The notice of a site that answers on neither link guesses "the site";
/// `c` settles it with the site check, on the host the service named.
#[test]
fn a_site_silent_on_both_links_offers_the_site_check_for_its_host() {
    let mut app = on_status();
    arrive(&mut app, silent_on_both_links(SITE));
    arrive(&mut app, tunnel_found());
    to_feed(&mut app);
    press(&mut app, KeyCode::Down);
    assert!(
        feed_text(&app).contains("c: Check site…"),
        "{}",
        feed_text(&app)
    );
    press(&mut app, KeyCode::Char('c'));
    assert_eq!(app.screen, ScreenId::Diagnostics);
    let fake = FakeService::new(ConnectionStatus::Connected);
    fake.answer(
        IpcOperationName::SiteCheckRun,
        json!({ "state": "running", "host": SITE }),
    );
    drain(&mut app, &fake);
    assert_eq!(
        fake.sent(IpcOperationName::SiteCheckRun),
        [json!({ "host": SITE })]
    );
}

/// Line mode names the notice by its number; a notice about something else
/// has no site to check.
#[test]
fn line_mode_checks_the_site_a_notice_names() {
    let mut app = on_status();
    let status = screen(ScreenId::Status);
    arrive(&mut app, tunnel_found());
    arrive(&mut app, silent_on_both_links(SITE));
    assert!(status.on_line(&mut app, "c 1"));
    assert_eq!(app.screen, ScreenId::Status, "notice 1 names no site");
    assert!(status.on_line(&mut app, "c 2"));
    assert_eq!(app.screen, ScreenId::Diagnostics);
    assert_eq!(app.inspect.site.host(), SITE);
}

/// `v` on a chosen block asks about that block, not the newest one.
#[test]
fn v_asks_about_the_chosen_block() {
    let mut app = on_status();
    arrive(&mut app, blocked("older.example", "", "blocked-by-rule"));
    arrive(&mut app, blocked("newer.example", "", "unattributed"));
    to_feed(&mut app);
    assert!(
        feed_text(&app).contains("v: Through additional"),
        "{}",
        feed_text(&app)
    );
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Char('v'));
    assert_eq!(app.block_route.asking.as_deref(), Some("older.example"));
}

/// Routed from the feed, the block notice has done its job and closes, as the
/// tray's does; a route that failed keeps it for another try.
#[test]
fn a_block_routed_from_the_feed_closes_and_a_failed_route_keeps_it() {
    for works in [true, false] {
        let mut app = on_status();
        arrive(&mut app, blocked("older.example", "", "blocked-by-rule"));
        to_feed(&mut app);
        press(&mut app, KeyCode::Char('v'));
        assert!(crate::block_route::answer(&mut app, true));
        let fake = FakeService::new(ConnectionStatus::Connected);
        if works {
            fake.answer(
                IpcOperationName::BlockNoticeRouteToSecondary,
                json!({ "authored": true }),
            );
            fake.answer(IpcOperationName::RulesList, json!({ "rows": [] }));
        }
        drain(&mut app, &fake);
        let still_there = app
            .notices
            .iter()
            .any(|n| n.shown_body(false).contains("older.example") && n.id == 1);
        assert_eq!(still_there, !works, "works={works}: {:?}", titles(&app));
    }
}

/// A block no rule can answer neither offers nor takes `v`.
#[test]
fn a_block_a_rule_cannot_answer_offers_no_route() {
    let mut app = on_status();
    arrive(&mut app, blocked(SITE, "", "route-unavailable"));
    to_feed(&mut app);
    assert!(!feed_text(&app).contains("v: "), "{}", feed_text(&app));
    press(&mut app, KeyCode::Char('v'));
    assert!(app.block_route.asking.is_none());
}

/// H hides the addresses at once, says so, and the choice outlives the run.
#[test]
fn hiding_addresses_takes_effect_at_once_and_is_kept() {
    let dir = Scratch::new("feed-hide-addresses");
    let path = dir.path().join("tui.json");
    let mut app = on_status();
    app.settings.prefs_path = Some(path.clone());
    arrive(&mut app, blocked(SITE, "", "blocked-by-rule"));
    to_feed(&mut app);
    assert!(feed_text(&app).contains(SITE));

    press(&mut app, KeyCode::Char('H'));

    let shown = feed_text(&app);
    assert!(!shown.contains(SITE), "{shown}");
    assert!(
        shown.contains("Block notifications no longer show addresses."),
        "{shown}"
    );
    assert!(crate::screens::settings::prefs::load(&path).hide_block_addresses);
    press(&mut app, KeyCode::Char('H'));
    assert!(feed_text(&app).contains(SITE));
}

/// Line mode names notices by the number they show, which a newer arrival
/// does not change; an answer's digit never opens a screen.
#[test]
fn line_mode_acts_on_notices_by_number() {
    let fake = muting_service(json!([]));
    let mut app = on_status();
    let status = screen(ScreenId::Status);
    arrive(&mut app, blocked("one.example", "", "blocked-by-rule"));
    arrive(&mut app, blocked("two.example", "", "blocked-by-rule"));
    arrive(&mut app, tunnel_found());

    assert!(status.on_line(&mut app, "x 2"));
    assert_eq!(app.notices.iter().map(|n| n.id).collect::<Vec<_>>(), [1, 3]);

    assert!(status.on_line(&mut app, "x 9"));
    assert!(feed_text(&app).contains("No notification has the number 9."));
    assert_eq!(app.notices.len(), 2);

    assert!(status.on_line(&mut app, "s 1"));
    assert!(status.captures_keys(&app), "the answer is read first");
    assert!(status.on_line(&mut app, "8"), "no such answer, no screen");
    assert_eq!(app.screen, ScreenId::Status);
    assert!(status.on_line(&mut app, "2"));
    drain(&mut app, &fake);
    assert_eq!(
        fake.sent(IpcOperationName::BlockNoticeMutesSet),
        vec![json!({
            "scope": { "kind": "host", "host": "one.example" },
            "until-unix-ms": NOW_MS + 60 * 60 * 1000
        })]
    );

    assert!(status.on_line(&mut app, "H"));
    assert!(app.settings.prefs.hide_block_addresses);
    assert!(status.on_line(&mut app, "X"));
    assert!(app.notices.is_empty());
}

/// Line mode offers every feed command under the screen.
#[test]
fn line_mode_lists_the_feed_commands() {
    let commands = screen(ScreenId::Status).plain_help();
    for k in [PLAIN_DISMISS, PLAIN_MUTE, PLAIN_BLOCK, PLAIN_SITE] {
        assert!(commands.contains(&k), "{}", k.id);
    }
}
