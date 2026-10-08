#![allow(clippy::expect_used)]

use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use nrr_ipc_client::ConnectionStatus;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::product_identity::TUN_ADAPTER_NAME;
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use serde_json::{json, Value};

use super::*;
use crate::backend::BackendEvent;
use crate::full::{draw, handle_key, RenderOptions};
use crate::link::Link;
use crate::plain::PlainSession;
use crate::screens::ScreenId;
use crate::testing::{
    assert_snapshot, missing_from_locales, snapshot_json, texts_en, FakeService, Fixture,
};

const WIFI: &str = "{00000000-0000-0000-0000-000000000003}";
const HOST_ONLY: &str = "{00000000-0000-0000-0000-000000000004}";

fn adapter(base: &Value, id: &str, name: &str, kind: &str) -> Value {
    let mut row = base.clone();
    row["persistent-id"] = json!(id);
    row["adapter-name"] = json!(id);
    row["name"] = json!(name);
    // A description equal to the name adds nothing, so the name reads alone.
    row["interface-description"] = json!(name);
    row["kind"] = json!(kind);
    row
}

/// Main and additional bound, plus an unbound Wi-Fi, a host-only virtual
/// adapter with no way out, and the product's own tunnel.
fn machine() -> Value {
    let mut snapshot = snapshot_json(&Fixture::healthy());
    let base = snapshot["adapters"]["rows"][0].clone();
    let wifi = adapter(&base, WIFI, "Wi-Fi", "wifi");
    let mut host_only = adapter(&base, HOST_ONLY, "Host-only Network", "virtual");
    host_only["gateway"] = json!("-");
    host_only["derived-assessment"]["virtual-interface-likelihood"] = json!("likely");
    let own = adapter(
        &base,
        "{00000000-0000-0000-0000-0000000000ff}",
        TUN_ADAPTER_NAME,
        "tunnel",
    );
    let rows = snapshot["adapters"]["rows"]
        .as_array_mut()
        .expect("fixture rows");
    rows.extend([wifi, host_only, own]);
    snapshot
}

fn app_with(snapshot: Value) -> AppState {
    let texts = texts_en();
    let mut app = AppState::new(ScreenId::Interfaces, false);
    app.apply(BackendEvent::Link(Link::Connected), &texts, Instant::now());
    let parsed = serde_json::from_value(snapshot).expect("snapshot parses");
    app.apply(
        BackendEvent::Snapshot(Box::new(parsed)),
        &texts,
        Instant::now(),
    );
    // The re-read a connection starts is not what these tests look at.
    app.outbox.take();
    app
}

fn service() -> FakeService {
    let fake = FakeService::new(ConnectionStatus::Connected);
    let snapshot = machine();
    fake.answer(
        IpcOperationName::RoutePolicyUpdate,
        snapshot["route-policy"].clone(),
    );
    fake.answer(IpcOperationName::SnapshotInitialGet, snapshot);
    fake
}

fn run_jobs(app: &mut AppState, fake: &FakeService) -> usize {
    let jobs = app.outbox.take();
    let count = jobs.len();
    for job in jobs {
        let reply = job(fake);
        (reply.0)(app);
    }
    count
}

fn press(app: &mut AppState, c: char) {
    handle_key(
        app,
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE),
        &texts_en(),
    );
}

fn choose(app: &mut AppState, name: &str) {
    let index = rows(app)
        .iter()
        .position(|row| row.name == name)
        .expect("the adapter is listed");
    app.interfaces.cursor = index;
}

fn render(app: &AppState, width: u16, height: u16) -> String {
    let texts = texts_en();
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
    let options = RenderOptions {
        colour: true,
        ascii: false,
    };
    terminal
        .draw(|frame| draw(frame, app, &texts, options, Instant::now()))
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

#[test]
fn every_key_is_in_both_locale_files() {
    let missing = missing_from_locales(k::ALL);
    assert!(missing.is_empty(), "{missing:?}");
}

#[test]
fn the_list_has_roles_from_the_bindings_and_never_our_own_tunnel() {
    let app = app_with(machine());
    let rows = rows(&app);
    let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(
        names,
        ["Ethernet", "Example Tunnel", "Wi-Fi", "Host-only Network"],
        "bound first, the product's tunnel left out"
    );
    assert_eq!(rows[0].selected_role.as_deref(), Some("primary"));
    assert_eq!(rows[1].selected_role.as_deref(), Some("secondary"));
    assert_eq!(rows[2].selected_role, None);
}

#[test]
fn a_role_write_sends_the_whole_policy_with_the_new_binding() {
    let fake = service();
    let mut app = app_with(machine());
    choose(&mut app, "Wi-Fi");
    press(&mut app, 's');
    assert_eq!(app.interfaces.busy, Some(Busy::Saving));
    assert_eq!(run_jobs(&mut app, &fake), 1);

    let sent = fake.sent(IpcOperationName::RoutePolicyUpdate);
    assert_eq!(sent.len(), 1, "one write");
    let request = &sent[0];
    assert_eq!(request["secondary"]["stable-id"], json!(WIFI));
    assert_eq!(request["secondary"]["user-confirmed"], json!(true));
    assert_eq!(
        request["primary"]["stable-id"],
        json!("{00000000-0000-0000-0000-000000000001}"),
        "the other slot rides back unchanged"
    );
    for field in [
        "kill-switch-protocols",
        "include-subdomains",
        "doh-lockdown-scope",
    ] {
        assert!(
            request.get(field).is_some(),
            "{field} is carried, not left to a default"
        );
    }
    assert_eq!(request["binding-source"], json!("user-assigned"));
    assert_eq!(
        request["apply-only"],
        json!(["secondary"]),
        "only the slot changed, so a concurrent tray write survives"
    );
    assert_eq!(
        fake.operations()[..2],
        [
            IpcOperationName::SnapshotInitialGet,
            IpcOperationName::RoutePolicyUpdate
        ],
        "the write is built on a fresh read"
    );
    assert_eq!(app.interfaces.busy, None);
    assert!(matches!(app.interfaces.outcome, Some(Outcome::Changed(_))));
}

#[test]
fn pressing_the_held_role_again_unassigns_it() {
    let fake = service();
    let mut app = app_with(machine());
    choose(&mut app, "Example Tunnel");
    press(&mut app, 's');
    run_jobs(&mut app, &fake);
    let request = &fake.sent(IpcOperationName::RoutePolicyUpdate)[0];
    assert!(
        request.get("secondary").is_none(),
        "unbinding leaves the slot out"
    );
    assert!(request.get("primary").is_some());
}

#[test]
fn one_adapter_never_takes_both_roles() {
    let mut app = app_with(machine());
    choose(&mut app, "Ethernet");
    press(&mut app, 's');
    assert_eq!(app.interfaces.outcome, Some(Outcome::Exclusive));
    assert!(app.outbox.take().is_empty(), "nothing was sent");
}

#[test]
fn an_adapter_with_no_way_out_is_bound_only_after_the_warning() {
    let fake = service();
    let mut app = app_with(machine());
    choose(&mut app, "Host-only Network");
    press(&mut app, 'p');
    assert!(matches!(
        app.interfaces.question,
        Some(Question::Unroutable { .. })
    ));
    assert!(app.outbox.take().is_empty());
    let picture = render(&app, 140, 50);
    assert!(
        picture.contains("This adapter cannot carry traffic out"),
        "{picture}"
    );
    assert!(picture.contains("Assign anyway"), "{picture}");

    // The question takes the keys, even with the menu focused.
    handle_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        &texts_en(),
    );
    assert_eq!(run_jobs(&mut app, &fake), 1);
    let request = &fake.sent(IpcOperationName::RoutePolicyUpdate)[0];
    assert_eq!(request["primary"]["stable-id"], json!(HOST_ONLY));
}

#[test]
fn without_the_service_nothing_is_written() {
    let texts = texts_en();
    let mut app = app_with(machine());
    app.apply(BackendEvent::Link(Link::Stopped), &texts, Instant::now());
    choose(&mut app, "Wi-Fi");
    press(&mut app, 's');
    assert_eq!(app.interfaces.outcome, Some(Outcome::NeedsService));
    assert!(app.outbox.take().is_empty());
}

#[test]
fn placeholder_rows_take_no_role() {
    let mut snapshot = machine();
    snapshot["adapters"]["data-source"] = json!("fallback-mock");
    let mut app = app_with(snapshot);
    choose(&mut app, "Wi-Fi");
    press(&mut app, 's');
    assert_eq!(app.interfaces.outcome, Some(Outcome::Placeholder));
    let picture = render(&app, 140, 50);
    assert!(picture.contains("These are not your adapters"), "{picture}");
}

#[test]
fn the_external_address_check_runs_only_when_asked() {
    let fake = service();
    fake.answer(
        IpcOperationName::InterfacesRefreshRequest,
        machine()["adapters"].clone(),
    );
    let mut app = app_with(machine());
    press(&mut app, 'x');
    assert_eq!(app.interfaces.busy, Some(Busy::Checking));
    run_jobs(&mut app, &fake);
    assert_eq!(app.interfaces.outcome, Some(Outcome::ProbeDone));
    assert!(fake
        .operations()
        .contains(&IpcOperationName::InterfacesRefreshRequest));
}

#[test]
fn interfaces_screen_snapshot() {
    let mut app = app_with(machine());
    choose(&mut app, "Wi-Fi");
    let wide = render(&app, 140, 50);
    assert!(wide.contains("> 3. Wi-Fi"), "{wide}");
    assert!(wide.contains("Main connection: Ethernet"), "{wide}");
    assert!(!wide.contains(TUN_ADAPTER_NAME), "{wide}");
    assert_snapshot("interfaces-80x24", &render(&app, 80, 24));
}

#[test]
fn line_mode_assigns_by_numbered_questions() {
    let texts = texts_en();
    let fake = service();
    let mut app = app_with(machine());
    let mut session = PlainSession::new(Vec::new());
    session.start(&app, &texts).expect("start");
    for answer in ["a", "3", "2"] {
        session.input(answer, &mut app, &texts).expect("answer");
    }
    assert_eq!(
        app.screen,
        ScreenId::Interfaces,
        "a number answered, not a jump"
    );
    run_jobs(&mut app, &fake);
    session.changed(&app, &texts).expect("result");
    let text = String::from_utf8(session.into_inner()).expect("UTF-8");
    assert!(text.contains("Which adapter?"), "{text}");
    assert!(text.contains("What should Wi-Fi carry?"), "{text}");
    assert!(text.contains("Additional connection: Wi-Fi."), "{text}");
    let request = &fake.sent(IpcOperationName::RoutePolicyUpdate)[0];
    assert_eq!(request["secondary"]["stable-id"], json!(WIFI));
    assert_snapshot("interfaces-plain", &text);
}
