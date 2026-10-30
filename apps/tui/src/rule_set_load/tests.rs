#![allow(clippy::expect_used)]

use std::time::{Duration, Instant};

use nrr_ipc_client::ConnectionStatus;
use nrr_shared::ipc::IpcOperationName;
use serde_json::json;

use super::*;
use crate::link::Link;
use crate::testing::{app_at, missing_from_locales, texts_en, FakeService, StoppedService};

#[test]
fn every_key_is_in_both_locale_files() {
    let missing = missing_from_locales(&keys());
    assert!(missing.is_empty(), "{missing:?}");
}

fn answering() -> FakeService {
    let fake = FakeService::new(ConnectionStatus::Connected);
    fake.answer(
        IpcOperationName::PrincipalDataCount,
        json!({ "other-principals": 0 }),
    );
    fake
}

#[test]
fn a_stopped_service_is_started_and_answers_before_the_set_goes() {
    let fake = answering();
    let manager = StoppedService { start: Ok(()) };
    assert!(start_service(Some(&manager), &fake, Duration::ZERO).is_ok());
    assert_eq!(fake.operations(), [IpcOperationName::PrincipalDataCount]);
}

#[test]
fn a_refused_start_is_told_as_wanting_rights() {
    let fake = answering();
    let manager = StoppedService {
        start: Err(ServiceControlError::AccessDenied),
    };
    let why = start_service(Some(&manager), &fake, Duration::ZERO).expect_err("refused");
    assert_eq!(why.words(&texts_en()), texts_en().get(NO_RIGHTS));
    assert!(
        fake.operations().is_empty(),
        "nothing asked of a service not up"
    );
}

#[test]
fn a_started_service_that_never_answers_is_not_called_up() {
    let fake = FakeService::new(ConnectionStatus::Connected);
    let manager = StoppedService { start: Ok(()) };
    assert!(matches!(
        start_service(Some(&manager), &fake, Duration::ZERO),
        Err(StartFailure::Silent)
    ));
}

#[test]
fn the_feed_line_names_the_set_and_its_count() {
    let mut app = app_at(Link::Connected, None);
    let before = app.notices.len();
    applied(
        &mut app,
        // A shipped set with no locale name falls back to its folder.
        SetName::keyed(
            ["rules", "bundled-preset", "name", "none"].join("."),
            "my-set".into(),
        ),
        67,
    );
    announce(&mut app, &texts_en(), Instant::now());
    let notice = app.notices.last().expect("told in the feed");
    assert_eq!(app.notices.len(), before + 1);
    assert_eq!(notice.title, texts_en().get(APPLIED_TITLE));
    assert!(notice.body.contains("«my-set»"), "{}", notice.body);
    assert!(notice.body.contains("67 rules"), "{}", notice.body);
}

#[test]
fn a_set_that_could_not_reach_the_service_says_why() {
    let mut app = app_at(Link::Stopped, None);
    not_applied(
        &mut app,
        SetName::of_path(std::path::Path::new("/sets/home/rules_primary.txt")),
        StartFailure::Control(ServiceControlError::AccessDenied),
    );
    announce(&mut app, &texts_en(), Instant::now());
    let notice = app.notices.last().expect("told in the feed");
    assert_eq!(notice.title, texts_en().get(NOT_APPLIED_TITLE));
    assert!(notice.body.contains("«home»"), "{}", notice.body);
    assert!(
        notice.body.contains(&texts_en().get(NO_RIGHTS)),
        "{}",
        notice.body
    );
}
