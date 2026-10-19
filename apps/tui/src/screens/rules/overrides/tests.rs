#![allow(clippy::expect_used)]

use std::time::Instant;

use nrr_ipc_client::ConnectionStatus;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::RuleOverrideDto;
use serde_json::json;

use super::*;
use crate::backend::BackendEvent;
use crate::link::Link;
use crate::screens::suggestions::tests::drain;
use crate::screens::{screen, ScreenId};
use crate::testing::{app_at, missing_from_locales, texts_en, FakeService, Fixture};

/// A site root this platform's protection holds as a folder many programs
/// share, written as the rules file writes it.
fn site_root() -> &'static str {
    match PlatformProfile::current().os {
        "linux" => "/var/www/*",
        "macos" => "/Library/WebServer/Documents/*",
        _ => r"C:\inetpub\*",
    }
}

fn on_rules_with_request() -> (FakeService, AppState) {
    let fake = FakeService::new(ConnectionStatus::Connected);
    fake.answer(
        IpcOperationName::RulesList,
        json!({
            "rows": [{
                "id": "r-1",
                "rule-type": "application",
                "match-value": format!("{} +override", site_root()),
                "target-route": "block",
                "enabled": true,
                "validation-status": "warning"
            }],
            "supported-rule-types": ["zone", "domain", "exact-ip", "application"]
        }),
    );
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    app.open(ScreenId::Rules);
    drain(&mut app, &fake);
    (fake, app)
}

fn line(app: &mut AppState, text: &str) {
    assert!(screen(app.screen).on_line(app, text), "{text:?}");
}

fn preview(token: &str) -> serde_json::Value {
    json!({
        "status": "ready",
        "token": token,
        "value": site_root().to_ascii_lowercase(),
        "route": "block",
        "reason": "shared-folder",
        "programs": 2,
        "service-accounts": ["S-1-5-18"],
        "breaks": ["other-programs"],
        "needs-administrator": true,
        "token-ttl-ms": 600000
    })
}

#[test]
fn every_key_is_in_both_locale_files() {
    let missing = missing_from_locales(text::ALL);
    assert!(missing.is_empty(), "{missing:?}");
}

/// A rule that asks is marked as waiting; the confirmation shows what the
/// service said, refuses a value that does not name the rule, and sends the
/// one that does with the term chosen.
#[test]
fn a_requested_rule_is_confirmed_with_its_value_typed_and_a_term() {
    let (fake, mut app) = on_rules_with_request();
    let texts = texts_en();
    let row = app.rules.table.rows[0].clone();
    assert!(
        mark(&app, &row, &texts).is_some(),
        "waiting for a confirmation"
    );
    assert!(!granted(&app, &row));

    fake.answer(IpcOperationName::RulesOverridePreview, preview("ovr-1"));
    line(&mut app, "P 1");
    drain(&mut app, &fake);
    let Mode::Override(confirm) = &app.rules.mode else {
        panic!("the confirmation is shown: {:?}", app.rules.mode);
    };
    let shown: String = lines(confirm, &texts)
        .iter()
        .map(|l| l.plain_text() + "\n")
        .collect();
    assert!(shown.contains("SYSTEM"), "{shown}");
    assert!(
        shown.contains(&texts.get(text::OVERRIDE_ADMINISTRATOR)),
        "{shown}"
    );

    line(&mut app, "3");
    line(&mut app, "/somewhere/else/*");
    assert!(fake.sent(IpcOperationName::RulesOverrideGrant).is_empty());
    assert!(matches!(app.rules.mode, Mode::Override(_)));

    fake.answer(
        IpcOperationName::RulesOverrideGrant,
        json!({ "granted": {
            "value": site_root().to_ascii_lowercase(),
            "route": "block",
            "reason": "shared-folder",
            "until-ms": 4_102_444_800_000_i64,
            "granted-at-ms": 1
        } }),
    );
    line(&mut app, site_root());
    drain(&mut app, &fake);
    let sent = fake.sent(IpcOperationName::RulesOverrideGrant);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["token"], "ovr-1");
    assert_eq!(sent[0]["term"], "one-week");
    assert!(matches!(app.rules.mode, Mode::List));
}

/// The snapshot's confirmations mark their rules with the term left, and the
/// filter by them shows exactly those.
#[test]
fn a_confirmed_rule_is_marked_and_filtered() {
    let (_fake, mut app) = on_rules_with_request();
    let texts = texts_en();
    let mut snapshot = Fixture::healthy().snapshot();
    snapshot.rule_overrides = vec![RuleOverrideDto {
        value: site_root().to_ascii_lowercase(),
        route: "block".into(),
        reason: "shared-folder".into(),
        until_ms: None,
        granted_at_ms: 1,
    }];
    app.apply(
        BackendEvent::Snapshot(Box::new(snapshot)),
        &texts,
        Instant::now(),
    );
    let row = app.rules.table.rows[0].clone();
    assert!(granted(&app, &row));
    let marked = mark(&app, &row, &texts).expect("marked");
    assert!(
        marked
            .text
            .contains(&texts.dynamic("rules.override.left.until-revoked", "")),
        "{marked:?}"
    );
    app.rules.table.filter = super::super::table::RouteFilter::Overridden;
    assert_eq!(app.rules.table.visible(), vec![0]);
}

#[test]
fn the_term_left_reads_in_the_largest_unit() {
    let texts = texts_en();
    assert_eq!(
        left_text(None, &texts),
        texts.dynamic("rules.override.left.until-revoked", "")
    );
    assert!(left_text(Some(now_ms() + 3 * 3_600_000), &texts).contains('3'));
}

/// The service's "needs an administrator" refusal reads as the one sentence
/// naming the way out, not as a bare `forbidden`.
#[test]
fn an_administrator_refusal_names_the_way_out() {
    let texts = texts_en();
    let message = format!(
        "{}: confirming a rule that reaches the system",
        nrr_shared::ipc_transport::NEEDS_ADMINISTRATOR_SLUG
    );
    let failure = Failure::of_call("forbidden", &message);
    assert_eq!(failure, Failure::NeedsAdministrator);
    assert_eq!(
        Failure::of_call("forbidden", "nope"),
        Failure::code("forbidden")
    );

    let preview: RuleOverridePreviewResponse =
        serde_json::from_value(preview("ovr-1")).expect("preview");
    let confirm = Confirm {
        preview,
        typed: String::new(),
        term: 0,
        sending: false,
        failure: Some(failure),
    };
    let shown: String = lines(&confirm, &texts)
        .iter()
        .map(|l| l.plain_text() + "\n")
        .collect();
    assert!(shown.contains("administrator rights"), "{shown}");
    assert!(!shown.contains("did not go through"), "{shown}");
}
