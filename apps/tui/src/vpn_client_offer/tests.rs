#![allow(clippy::expect_used)]

use std::time::Instant;

use nrr_shared::ipc_payloads::LinkProviderAppDto;

use super::*;
use crate::link::Link;
use crate::screens::settings::found_rows;
use crate::testing::{app_at, texts_en, Fixture};
use nrr_platform_api::{VpnCandidate, VpnCandidateSource};

/// The fixture binds "Example Tunnel" as the additional adapter.
const LINK: &str = "Example Tunnel";
const CLIENT: &str = r"C:\Program Files\Example\example-client.exe";
const OTHER: &str = r"C:\Program Files\Other VPN\othervpn.exe";

fn running(path: &str, name: &str) -> VpnCandidate {
    VpnCandidate {
        display_name: name.to_owned(),
        exe_path: Some(path.to_owned()),
        running: true,
        source: VpnCandidateSource::RunningProcess,
        interface: None,
    }
}

fn connected() -> AppState {
    app_at(Link::Connected, Some(&Fixture::healthy()))
}

#[test]
fn the_vpn_that_raised_the_link_is_offered_once_on_the_feed_and_listed_for_the_answer() {
    let mut app = connected();
    let rows = found_rows(&[
        running(CLIENT, "example-client.exe"),
        running(OTHER, "othervpn.exe"),
    ]);
    found(&mut app, LINK, rows);
    let texts = texts_en();
    announce(&mut app, &texts, Instant::now());
    announce(&mut app, &texts, Instant::now());

    assert_eq!(app.notices.len(), 1, "told once");
    let notice = &app.notices[0];
    assert_eq!(notice.title, "Is this your VPN?");
    assert!(
        notice.body.contains("example-client.exe"),
        "{}",
        notice.body
    );
    assert!(
        !notice.body.contains("othervpn"),
        "another vendor's VPN is not offered: {}",
        notice.body
    );
    assert!(notice.body.contains("(c2)"), "{}", notice.body);
    assert!(
        app.settings.providers.found.is_some(),
        "the row the notice points at is already listed"
    );

    // Asked once a run: the link coming up again says nothing more.
    check(&mut app);
    assert!(app.outbox.take().is_empty());
}

#[test]
fn nothing_is_offered_once_a_vpn_client_is_set() {
    let mut app = connected();
    if let Some(policy) = app.snapshot.as_mut().and_then(|s| s.route_policy.as_mut()) {
        policy.secondary_link_provider_apps = vec![LinkProviderAppDto {
            exe_path: CLIENT.to_owned(),
            display_name: "Example".to_owned(),
        }];
    }
    check(&mut app);
    assert!(app.outbox.take().is_empty(), "no scan at all");
    found(
        &mut app,
        LINK,
        found_rows(&[running(CLIENT, "example-client.exe")]),
    );
    announce(&mut app, &texts_en(), Instant::now());
    assert!(app.notices.is_empty());
}

#[test]
fn every_key_is_in_both_locale_files() {
    let missing = crate::testing::missing_from_locales(&[TITLE, BODY]);
    assert!(missing.is_empty(), "{missing:?}");
}
