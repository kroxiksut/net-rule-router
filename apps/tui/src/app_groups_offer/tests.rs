#![allow(clippy::expect_used)]

use std::time::Instant;

use nrr_ipc_client::ConnectionStatus;
use nrr_platform_api::app_group_discovery::AppDiscoverySource;

use super::*;
use crate::link::Link;
use crate::screens::settings::prefs;
use crate::screens::suggestions::tests::drain;
use crate::testing::{app_at, texts_en, FakeService, Fixture, Scratch};

fn found(kind: AppGroupKind, name: &str) -> DiscoveredApp {
    DiscoveredApp {
        kind,
        display_name: name.to_owned(),
        exe_path: None,
        running: false,
        source: AppDiscoverySource::InstalledProgram,
    }
}

fn five_programs() -> Vec<DiscoveredApp> {
    vec![
        found(AppGroupKind::KernelVirtualNet, "WSL"),
        found(AppGroupKind::Hypervisor, "QEMU"),
        found(AppGroupKind::AndroidEmulator, "Emu\u{1b}[2J"),
        found(AppGroupKind::Hypervisor, "DOSBox"),
        found(AppGroupKind::AndroidEmulator, "Nox"),
        found(AppGroupKind::AndroidEmulator, "MEmu"),
    ]
}

/// Connected, with a settings file of its own and the machine's scan replaced.
fn connected(dir: &Scratch, scan: fn() -> Vec<DiscoveredApp>) -> AppState {
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    app.app_groups_offer = AppGroupsOfferState {
        discover: scan,
        ..AppGroupsOfferState::default()
    };
    app.settings.prefs_path = Some(dir.path().join("tui.json"));
    app
}

fn run(app: &mut AppState) {
    let fake = FakeService::new(ConnectionStatus::Connected);
    check(app);
    drain(app, &fake);
    let texts = texts_en();
    announce(app, &texts, Instant::now());
    announce(app, &texts, Instant::now());
}

/// A program installed long before this one is told about once, by name, with
/// the rest counted; a kernel network, which no rule can route, is no reason;
/// a name the program reports never reaches the terminal as control codes.
#[test]
fn found_programs_are_told_once_and_not_again_after_a_restart() {
    let dir = Scratch::new("app-groups-offer");
    let mut app = connected(&dir, five_programs);
    let before = app.notices.len();
    run(&mut app);

    assert_eq!(app.notices.len(), before + 1, "told once");
    let body = &app.notices.last().expect("told").body;
    assert!(body.contains("QEMU"), "{body}");
    assert!(body.contains("DOSBox"), "{body}");
    assert!(
        !body.contains("WSL"),
        "a kernel network was offered: {body}"
    );
    assert!(body.contains("2 more found"), "{body}");
    assert!(body.contains("press g"), "{body}");
    assert!(!body.contains('\u{1b}'), "{body:?}");

    // The next run reads the settings file and stays quiet.
    let mut next = connected(&dir, five_programs);
    next.settings.prefs = prefs::load(&dir.path().join("tui.json"));
    let before = next.notices.len();
    run(&mut next);
    assert_eq!(next.notices.len(), before, "told again after a restart");
}

/// Nothing found says nothing, and a program installed later is still told.
#[test]
fn nothing_found_says_nothing_and_keeps_the_offer() {
    let dir = Scratch::new("app-groups-offer-none");
    let mut app = connected(&dir, || vec![found(AppGroupKind::KernelVirtualNet, "WSL")]);
    let before = app.notices.len();
    run(&mut app);
    assert_eq!(app.notices.len(), before);
    assert!(!app.settings.prefs.app_groups_offer_told);
}

#[test]
fn every_key_is_in_both_locale_files() {
    let missing = crate::testing::missing_from_locales(&[OFFER, MORE, TITLE, HOW]);
    assert!(missing.is_empty(), "{missing:?}");
}
