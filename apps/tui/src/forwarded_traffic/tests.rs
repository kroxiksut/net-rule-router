#![allow(clippy::expect_used)]

use std::time::Instant;

use serde_json::Value;

use super::*;
use crate::backend::BackendEvent;
use crate::link::Link;
use crate::testing::{app_at, snapshot_json, texts_en, Fixture};

/// The healthy fixture, plus WSL's adapter when `wsl`, with `answer` stored.
fn snapshot(wsl: bool, answer: &str) -> BackendEvent {
    let mut json = snapshot_json(&Fixture::healthy());
    if wsl {
        let rows = json["adapters"]["rows"].as_array_mut().expect("rows");
        let mut row = rows.first().cloned().expect("a row");
        row["name"] = Value::from("vEthernet (WSL (Hyper-V firewall))");
        row["persistent-id"] = Value::from("{00000000-0000-0000-0000-000000000009}");
        row["adapter-name"] = row["persistent-id"].clone();
        rows.push(row);
    }
    json["route-policy"]["forwarded-outage"] = Value::from(answer);
    BackendEvent::Snapshot(Box::new(
        serde_json::from_value(json).expect("fixture snapshot must parse"),
    ))
}

fn told(app: &AppState) -> usize {
    app.notices
        .iter()
        .filter(|n| n.title == "WSL or containers are running")
        .count()
}

/// Asked when WSL appears unanswered, once while it runs, and again after it
/// stopped and started.
#[test]
fn wsl_appearing_unanswered_is_asked_about_once_per_appearance() {
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    if !app.settings.supports.forwarded_traffic_guard {
        return;
    }
    let texts = texts_en();
    app.apply(snapshot(false, ""), &texts, Instant::now());
    assert_eq!(told(&app), 0, "no WSL, no question");
    app.apply(snapshot(true, ""), &texts, Instant::now());
    app.apply(snapshot(true, ""), &texts, Instant::now());
    assert_eq!(told(&app), 1, "asked once while it runs");
    let notice = app
        .notices
        .iter()
        .find(|n| n.title == "WSL or containers are running")
        .expect("the question");
    assert!(notice.body.contains("(c2)"), "{}", notice.body);
    app.apply(snapshot(false, ""), &texts, Instant::now());
    app.apply(snapshot(true, ""), &texts, Instant::now());
    assert_eq!(told(&app), 2, "asked again when it starts again");
}

#[test]
fn an_answered_wsl_is_not_asked_about() {
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    app.apply(snapshot(true, "unprotected"), &texts_en(), Instant::now());
    assert_eq!(told(&app), 0);
}

#[test]
fn every_key_is_in_both_locale_files() {
    let missing = crate::testing::missing_from_locales(&[
        keys::FORWARDED_TITLE,
        keys::FORWARDED_BODY,
        keys::ANSWER_IN_ROUTING_HINT,
    ]);
    assert!(missing.is_empty(), "{missing:?}");
}
