#![allow(clippy::expect_used)]

use nrr_ipc_client::ConnectionStatus;
use serde_json::json;

use super::super::items::{self, items, ItemId};
use super::super::Category;
use super::*;
use crate::link::Link;
use crate::testing::{app_at, missing_from_locales, texts_en, FakeService, Fixture};

const FIRST: &str = "C:\\Apps\\Alpha\\alpha-vpn.exe";
const SECOND: &str = "C:\\Apps\\Beta\\beta-vpn.exe";

fn policy_with(apps: &[(&str, &str)]) -> Value {
    json!({
        "route-policy": {
            "secondary-link-provider-apps": apps
                .iter()
                .map(|(p, n)| json!({ "exe-path": p, "display-name": n }))
                .collect::<Vec<_>>()
        }
    })
}

fn service(apps: &[(&str, &str)]) -> FakeService {
    let fake = FakeService::new(ConnectionStatus::Connected);
    fake.answer(Op::SnapshotInitialGet, policy_with(apps));
    fake.answer(Op::RouteLinkProviderSet, json!({}));
    fake
}

fn with_policy(apps: &[(&str, &str)]) -> AppState {
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    let policy = policy_with(apps)["route-policy"]
        .as_object()
        .cloned()
        .expect("object");
    app.settings.data.policy = Loadable::Ready(policy);
    app
}

fn run(app: &mut AppState, service: &FakeService) {
    for job in app.outbox.take() {
        (job(service).0)(app);
    }
}

fn said(app: &AppState) -> String {
    app.settings
        .message
        .as_ref()
        .map(|m| m.words.resolve(&texts_en()))
        .expect("a message")
}

#[test]
fn every_key_is_in_both_locale_files() {
    let missing = missing_from_locales(&keys());
    assert!(missing.is_empty(), "{missing:?}");
}

#[test]
fn the_confirmed_programs_are_listed_with_a_remove_row_each() {
    let app = with_policy(&[(FIRST, "Alpha"), (SECOND, "")]);
    let rows = items(&app, Category::Routing);
    let labels: Vec<String> = rows
        .iter()
        .filter(|i| matches!(i.id, ItemId::Provider(ProviderRow::Remove(_))))
        .map(|i| i.label.resolve(&texts_en()))
        .collect();
    assert_eq!(labels.len(), 2, "{labels:?}");
    assert!(
        labels[0].contains("Alpha") && labels[0].contains(FIRST),
        "{labels:?}"
    );
    assert!(labels[1].contains("beta-vpn.exe"), "{labels:?}");
}

#[test]
fn adding_a_path_writes_the_whole_set_with_the_new_program_last() {
    let fake = service(&[(FIRST, "Alpha")]);
    let mut app = with_policy(&[(FIRST, "Alpha")]);
    app.settings.providers.new = SECOND.to_owned();
    let job = activate(&mut app, ProviderRow::Add, Input::Run).expect("a write");
    app.outbox.push(job);
    run(&mut app, &fake);

    let sent = fake.sent(Op::RouteLinkProviderSet);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0]["role"], json!("secondary"));
    assert_eq!(
        sent[0]["link-provider-apps"],
        json!([
            { "exe-path": FIRST, "display-name": "Alpha" },
            { "exe-path": SECOND, "display-name": "beta-vpn.exe" }
        ])
    );
    assert!(said(&app).contains("beta-vpn.exe"), "{}", said(&app));
    assert!(app.settings.providers.new.is_empty());
}

#[test]
fn adding_nothing_is_refused_and_sends_nothing() {
    let mut app = with_policy(&[]);
    assert!(activate(&mut app, ProviderRow::Add, Input::Run).is_none());
    assert_eq!(said(&app), texts_en().get(NEED_PATH));
}

#[test]
fn removing_one_keeps_the_others_in_order() {
    let fake = service(&[(FIRST, "Alpha"), (SECOND, "Beta")]);
    let mut app = with_policy(&[(FIRST, "Alpha"), (SECOND, "Beta")]);
    let job = activate(&mut app, ProviderRow::Remove(0), Input::Run).expect("a write");
    app.outbox.push(job);
    run(&mut app, &fake);

    let sent = fake.sent(Op::RouteLinkProviderSet);
    assert_eq!(
        sent[0]["link-provider-apps"],
        json!([{ "exe-path": SECOND, "display-name": "Beta" }])
    );
    assert!(said(&app).contains("Alpha"), "{}", said(&app));
}

#[test]
fn the_change_starts_from_the_services_list_not_the_one_on_screen() {
    let fake = service(&[(FIRST, "Alpha"), (SECOND, "Beta")]);
    // The screen still shows only the first program; the service has two.
    let mut app = with_policy(&[(FIRST, "Alpha")]);
    app.settings.providers.new = "C:\\Apps\\Gamma\\gamma.exe".to_owned();
    let job = activate(&mut app, ProviderRow::Add, Input::Run).expect("a write");
    app.outbox.push(job);
    run(&mut app, &fake);
    let sent = fake.sent(Op::RouteLinkProviderSet);
    assert_eq!(
        sent[0]["link-provider-apps"].as_array().map(Vec::len),
        Some(3)
    );
}

#[test]
fn a_failed_write_says_so_and_keeps_the_typed_path() {
    let fake = FakeService::new(ConnectionStatus::Connected);
    fake.answer(Op::SnapshotInitialGet, policy_with(&[]));
    // No scripted answer for the write: the service did not take it.
    let mut app = with_policy(&[]);
    app.settings.providers.new = FIRST.to_owned();
    let job = activate(&mut app, ProviderRow::Add, Input::Run).expect("a write");
    app.outbox.push(job);
    run(&mut app, &fake);
    assert_eq!(app.settings.providers.new, FIRST);
    assert_eq!(
        app.settings.message.as_ref().map(|m| m.tone),
        Some(Some(crate::view::StateTone::Bad))
    );
}

#[test]
fn the_allowed_vpn_gateways_are_listed_and_removing_one_keeps_the_others() {
    let stored = json!([
        { "address": "198.51.100.7", "program": "" },
        { "address": "203.0.113.20", "program": FIRST }
    ]);
    let fake = service(&[]);
    fake.answer(
        Op::SnapshotInitialGet,
        json!({ "route-policy": {}, "confirmed-vpn-gateways": stored }),
    );
    fake.answer(
        Op::RouteVpnGatewaysSet,
        json!({ "gateways": [{ "address": "203.0.113.20", "program": FIRST }] }),
    );
    let mut app = with_policy(&[]);
    app.vpn_gateway_trust.confirmed = serde_json::from_value(stored).expect("gateways");

    let labels: Vec<String> = items(&app, Category::Routing)
        .iter()
        .filter(|i| matches!(i.id, ItemId::Provider(ProviderRow::RemoveGateway(_))))
        .map(|i| i.label.resolve(&texts_en()))
        .collect();
    assert_eq!(labels.len(), 2, "{labels:?}");
    assert!(
        labels[0].contains("198.51.100.7") && labels[0].contains("built into the system"),
        "{labels:?}"
    );
    assert!(
        labels[1].contains("203.0.113.20") && labels[1].contains("alpha-vpn.exe"),
        "{labels:?}"
    );

    let job = activate(&mut app, ProviderRow::RemoveGateway(0), Input::Run).expect("a write");
    app.outbox.push(job);
    run(&mut app, &fake);

    let sent = fake.sent(Op::RouteVpnGatewaysSet);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(
        sent[0]["gateways"],
        json!([{ "address": "203.0.113.20", "program": FIRST }])
    );
    assert_eq!(app.vpn_gateway_trust.confirmed.len(), 1);
    assert!(said(&app).contains("198.51.100.7"), "{}", said(&app));
}

#[test]
fn no_vpn_gateway_section_until_one_is_allowed() {
    let app = with_policy(&[]);
    let texts = texts_en();
    assert!(!items(&app, Category::Routing)
        .iter()
        .any(|i| i.label.resolve(&texts) == texts.get(GATEWAYS_TITLE)));
}

const ELSEWHERE: &str = "C:\\Apps\\Added\\elsewhere.exe";

fn found(path: &str, name: &str) -> VpnCandidate {
    VpnCandidate {
        display_name: name.to_owned(),
        exe_path: (!path.is_empty()).then(|| path.to_owned()),
        running: false,
        source: VpnCandidateSource::InstalledProgram,
        interface: None,
    }
}

fn with_found(apps: &[(&str, &str)], candidates: &[VpnCandidate]) -> AppState {
    let mut app = with_policy(apps);
    app.settings.providers.found = Some(found_rows(candidates));
    app
}

fn found_items(app: &AppState) -> Vec<(ItemId, items::Kind)> {
    items(app, Category::Routing)
        .into_iter()
        .filter(|i| matches!(i.id, ItemId::Provider(ProviderRow::Found(_))))
        .map(|i| (i.id, i.kind))
        .collect()
}

#[test]
fn every_found_program_shows_whether_it_is_confirmed() {
    let app = with_found(
        &[(FIRST, "Alpha"), (SECOND, "Beta")],
        &[
            found(FIRST, "Alpha"),
            found(SECOND, "Beta"),
            found("C:\\Apps\\Gamma\\gamma.exe", "Gamma"),
        ],
    );
    assert_eq!(
        found_items(&app),
        vec![
            (
                ItemId::Provider(ProviderRow::Found(0)),
                items::Kind::Toggle(true)
            ),
            (
                ItemId::Provider(ProviderRow::Found(1)),
                items::Kind::Toggle(true)
            ),
            (
                ItemId::Provider(ProviderRow::Found(2)),
                items::Kind::Toggle(false)
            ),
        ],
        "both confirmed programs read as ticked, not only the first"
    );
}

#[test]
fn a_program_found_without_its_file_cannot_be_ticked() {
    let app = with_found(&[], &[found("", "Corp Client")]);
    assert!(found_items(&app).is_empty());
    let texts = texts_en();
    assert!(items(&app, Category::Routing).iter().any(|i| i
        .label
        .resolve(&texts)
        .contains("Corp Client")
        && i.label.resolve(&texts).contains(&texts.get(FOUND_NO_FILE))));
}

#[test]
fn ticking_a_found_program_keeps_every_other_confirmed_one() {
    let stored = [(FIRST, "Alpha"), (ELSEWHERE, "Elsewhere")];
    let fake = service(&stored);
    let mut app = with_found(&stored, &[found(FIRST, "Alpha"), found(SECOND, "Beta")]);
    let job = activate(&mut app, ProviderRow::Found(1), Input::Toggle).expect("a write");
    app.outbox.push(job);
    run(&mut app, &fake);

    let sent = fake.sent(Op::RouteLinkProviderSet);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(
        sent[0]["link-provider-apps"],
        json!([
            { "exe-path": FIRST, "display-name": "Alpha" },
            { "exe-path": SECOND, "display-name": "Beta" },
            { "exe-path": ELSEWHERE, "display-name": "Elsewhere" }
        ])
    );
}

#[test]
fn unticking_a_found_program_removes_only_it() {
    let stored = [(FIRST, "Alpha"), (SECOND, "Beta"), (ELSEWHERE, "Elsewhere")];
    let fake = service(&stored);
    let mut app = with_found(&stored, &[found(FIRST, "Alpha"), found(SECOND, "Beta")]);
    let job = activate(&mut app, ProviderRow::Found(0), Input::Toggle).expect("a write");
    app.outbox.push(job);
    run(&mut app, &fake);

    let sent = fake.sent(Op::RouteLinkProviderSet);
    assert_eq!(
        sent[0]["link-provider-apps"],
        json!([
            { "exe-path": SECOND, "display-name": "Beta" },
            { "exe-path": ELSEWHERE, "display-name": "Elsewhere" }
        ])
    );
    assert!(said(&app).contains("Alpha"), "{}", said(&app));
}

#[test]
fn the_scan_row_is_there_before_any_scan() {
    let app = with_policy(&[]);
    assert!(items(&app, Category::Routing)
        .iter()
        .any(|i| i.id == ItemId::Provider(ProviderRow::Scan)));
    assert!(app.settings.providers.found.is_none());
}
