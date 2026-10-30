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
    app.interfaces.cursor_key = None;
    // Choosing a row is done in the list, which has the focus then.
    app.focus = crate::state::Focus::Feed;
}

/// The list re-sorts under the cursor; the chosen adapter stays chosen, so
/// `p` never lands on a neighbour.
#[test]
fn the_cursor_follows_its_adapter_when_the_list_reorders() {
    let mut app = app_with(machine());
    // Navigation records the adapter, as a keypress does.
    let list = rows(&app);
    set_cursor(&mut app, &list, 2);
    let chosen = selected(&app).expect("a row is chosen");

    let mut snapshot = machine();
    snapshot["adapters"]["rows"]
        .as_array_mut()
        .expect("rows")
        .reverse();
    let parsed = serde_json::from_value(snapshot).expect("snapshot parses");
    app.apply(
        BackendEvent::Snapshot(Box::new(parsed)),
        &texts_en(),
        Instant::now(),
    );
    app.outbox.take();
    let after = selected(&app).expect("a row is chosen");
    assert_eq!(row_key(&after), row_key(&chosen));
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

/// From the menu the first row (the main adapter) is under the cursor: `p`
/// there must not unbind it before the list has the focus.
#[test]
fn a_role_letter_from_the_menu_first_gives_the_list_the_focus() {
    let fake = service();
    let mut app = app_with(machine());
    assert_eq!(app.focus, crate::state::Focus::Menu);
    press(&mut app, 'p');
    assert_eq!(run_jobs(&mut app, &fake), 0, "nothing written");
    assert!(fake.sent(IpcOperationName::RoutePolicyUpdate).is_empty());
    assert_eq!(app.focus, crate::state::Focus::Feed);
    press(&mut app, 'p');
    run_jobs(&mut app, &fake);
    assert_eq!(fake.sent(IpcOperationName::RoutePolicyUpdate).len(), 1);
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

    // The safe answer is highlighted: Enter alone binds nothing.
    handle_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        &texts_en(),
    );
    assert_eq!(app.interfaces.outcome, Some(Outcome::Cancelled));
    assert!(app.outbox.take().is_empty(), "nothing was sent");

    // The question takes the keys, even with the menu focused.
    press(&mut app, 'p');
    for code in [KeyCode::Up, KeyCode::Enter] {
        handle_key(
            &mut app,
            KeyEvent::new(code, KeyModifiers::NONE),
            &texts_en(),
        );
    }
    assert_eq!(run_jobs(&mut app, &fake), 1);
    let request = &fake.sent(IpcOperationName::RoutePolicyUpdate)[0];
    assert_eq!(request["primary"]["stable-id"], json!(HOST_ONLY));
}

fn with_leak_protection(mode: &str, level: &str) -> Value {
    let mut snapshot = machine();
    snapshot["route-policy"]["mode"] = json!(mode);
    snapshot["route-policy"]["leak-protection"] = json!(level);
    snapshot
}

#[test]
fn removing_the_additional_role_under_everything_asks_first() {
    let fake = service();
    let mut app = app_with(with_leak_protection("prefer-primary", "everything"));
    choose(&mut app, "Example Tunnel");
    press(&mut app, 's');
    assert!(matches!(
        app.interfaces.question,
        Some(Question::HoldsNow { .. })
    ));
    assert!(app.outbox.take().is_empty(), "nothing was sent yet");
    let picture = render(&app, 140, 50);
    assert!(
        picture.contains("Leak protection will hold all traffic"),
        "{picture}"
    );

    // The safe answer is highlighted: Enter alone changes nothing.
    handle_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        &texts_en(),
    );
    assert_eq!(app.interfaces.outcome, Some(Outcome::Cancelled));
    assert!(app.outbox.take().is_empty(), "nothing was sent");

    press(&mut app, 's');
    for code in [KeyCode::Up, KeyCode::Enter] {
        handle_key(
            &mut app,
            KeyEvent::new(code, KeyModifiers::NONE),
            &texts_en(),
        );
    }
    assert_eq!(run_jobs(&mut app, &fake), 1);
    let request = &fake.sent(IpcOperationName::RoutePolicyUpdate)[0];
    assert!(request.get("secondary").is_none(), "the role was removed");
}

#[test]
fn routed_sites_under_the_additional_default_route_asks_as_everything() {
    let mut app = app_with(with_leak_protection(
        "prefer-secondary-when-available",
        "sites",
    ));
    choose(&mut app, "Example Tunnel");
    press(&mut app, 's');
    assert!(matches!(
        app.interfaces.question,
        Some(Question::HoldsNow { .. })
    ));
}

#[test]
fn removing_the_additional_role_under_routed_sites_asks_nothing() {
    let mut app = app_with(with_leak_protection("prefer-primary", "sites"));
    choose(&mut app, "Example Tunnel");
    press(&mut app, 's');
    assert_eq!(app.interfaces.question, None);
    assert_eq!(app.outbox.take().len(), 1, "the write went out at once");
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
fn a_panel_cut_by_a_small_terminal_says_so_and_a_roomy_one_does_not() {
    let mut app = app_with(machine());
    choose(&mut app, "Wi-Fi");
    let small = render(&app, 80, 24);
    assert!(small.contains("more rows"), "{small}");
    assert!(
        small.contains("> 3. Wi-Fi"),
        "the chosen row stays in view:
{small}"
    );
    let roomy = render(&app, 140, 50);
    assert!(!roomy.contains("more rows"), "{roomy}");
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
    assert!(
        text.contains("Additional connection (e.g. VPN): Wi-Fi."),
        "{text}"
    );
    let request = &fake.sent(IpcOperationName::RoutePolicyUpdate)[0];
    assert_eq!(request["secondary"]["stable-id"], json!(WIFI));
    assert_snapshot("interfaces-plain", &text);
}

fn names(app: &AppState) -> Vec<String> {
    rows(app).iter().map(|row| row.name.clone()).collect()
}

fn view_text(app: &AppState) -> String {
    let view = InterfacesScreen.view(app, &texts_en());
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

fn enter(app: &mut AppState) {
    handle_key(
        app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        &texts_en(),
    );
}

/// The window's search, unavailable switch and sort, from the keyboard: a
/// long list on a docked laptop is found by typing, not by scrolling.
#[test]
fn the_list_is_searched_narrowed_and_reordered_as_in_the_window() {
    let mut snapshot = machine();
    snapshot["adapters"]["rows"][2]["availability"] = json!("unavailable");
    let unavailable = snapshot["adapters"]["rows"][2]["name"]
        .as_str()
        .expect("name")
        .to_owned();
    let mut app = app_with(snapshot);
    let all = names(&app);

    press(&mut app, '/');
    for c in "host".chars() {
        press(&mut app, c);
    }
    enter(&mut app);
    assert_eq!(names(&app), vec!["Host-only Network".to_string()]);
    assert!(
        view_text(&app).contains("Find: host"),
        "{}",
        view_text(&app)
    );

    press(&mut app, '/');
    for _ in 0..4 {
        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE),
            &texts_en(),
        );
    }
    enter(&mut app);
    assert_eq!(names(&app), all, "an empty search shows everything again");

    press(&mut app, 'u');
    assert!(!names(&app).contains(&unavailable), "{:?}", names(&app));
    press(&mut app, 'u');

    press(&mut app, 'o');
    let vpn_first = names(&app);
    let host_only = vpn_first
        .iter()
        .position(|n| n == "Host-only Network")
        .expect("listed");
    let wifi = vpn_first.iter().position(|n| n == "Wi-Fi").expect("listed");
    assert!(
        host_only < wifi,
        "a likely virtual adapter leads the VPN order: {vpn_first:?}"
    );
}

/// A bound additional adapter the OS reports switched off says so, and says
/// to turn it back on rather than to send the binding again.
#[test]
fn a_switched_off_remembered_adapter_says_to_turn_it_back_on() {
    let mut snapshot = machine();
    snapshot["route-policy"]["secondary"]["stable-id"] = json!("{gone}");
    snapshot["route-policy"]["secondary"]["display-name"] = json!("Corp VPN");
    snapshot["enforcement-status"] = json!([{ "status": "secondary-down", "role": "secondary" }]);
    let app = app_with(snapshot);
    let text = view_text(&app);
    assert!(text.contains("remembered · switched off"), "{text}");
    assert!(text.contains("Turn it back on"), "{text}");
}

/// `e` sends the bindings the service holds back to it, so it finds the
/// adapter again.
#[test]
fn resend_writes_the_route_policy_again() {
    let fake = service();
    let mut app = app_with(machine());
    press(&mut app, 'e');
    run_jobs(&mut app, &fake);
    assert_eq!(fake.sent(IpcOperationName::RoutePolicyUpdate).len(), 1);
    assert!(
        view_text(&app).contains("sent to the service again"),
        "{}",
        view_text(&app)
    );
}

/// The bound additional adapter is a dead copy of a stock VPN driver while
/// another copy is connected: the details say which, as the window's card does.
#[test]
fn a_dead_bound_tap_names_the_connected_copy_of_its_driver() {
    let with_sibling = |sibling_availability: &str| {
        let mut snapshot = machine();
        let rows = snapshot["adapters"]["rows"]
            .as_array_mut()
            .expect("fixture rows");
        let base = rows[0].clone();
        let bound = rows
            .iter_mut()
            .find(|row| row["name"] == "Example Tunnel")
            .expect("the additional adapter");
        bound["availability"] = json!("unavailable");
        bound["interface-description"] = json!("TAP-Windows Adapter V9 #3");
        let mut sibling = adapter(
            &base,
            "{00000000-0000-0000-0000-000000000005}",
            "Ethernet 5",
            "tunnel",
        );
        sibling["interface-description"] = json!("TAP-Windows Adapter V9 #5");
        sibling["availability"] = json!(sibling_availability);
        rows.push(sibling);
        let mut app = app_with(snapshot);
        choose(&mut app, "Example Tunnel");
        view_text(&app)
    };
    let live = with_sibling("available");
    assert!(
        live.contains("another adapter of the same kind is: Ethernet 5"),
        "{live}"
    );
    let idle = with_sibling("unavailable");
    assert!(
        idle.contains("other adapters of the same kind are on this computer"),
        "{idle}"
    );

    // A connected bound adapter has nothing to warn about.
    let mut app = app_with(machine());
    choose(&mut app, "Example Tunnel");
    assert!(!view_text(&app).contains("of the same kind"));
}
