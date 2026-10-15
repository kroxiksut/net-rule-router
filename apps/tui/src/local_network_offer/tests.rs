#![allow(clippy::expect_used)]

use std::time::Instant;

use nrr_ipc_client::ConnectionStatus;
use nrr_shared::ipc::IpcOperationName;
use serde_json::json;

use super::*;
use crate::link::Link;
use crate::screens::suggestions::tests::drain;
use crate::testing::{app_at, texts_en, FakeService, Fixture};

/// Connected, with the read the connect started (and `app_at` discarded) not
/// left pending.
fn connected() -> AppState {
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    app.local_network_offer = LocalNetworkOfferState::default();
    app
}

fn service(networks: serde_json::Value) -> FakeService {
    let fake = FakeService::new(ConnectionStatus::Connected);
    fake.answer(
        IpcOperationName::LocalNetworksGet,
        json!({ "networks": networks }),
    );
    fake
}

/// The window's banner, on the feed: the first network waiting for an answer,
/// how many more, and where to answer. One with a reason is never asked about.
#[test]
fn a_network_waiting_for_an_answer_is_told_once_on_the_feed() {
    let fake = service(json!([
        { "cidr": "0.0.0.0/1", "kind": "main-link", "adapter": "Ethernet",
          "allowed": false, "decided-by-user": true, "reason": "too-wide" },
        { "cidr": "2001:db8:5:7::/64", "kind": "main-link", "adapter": "Ethernet",
          "allowed": false, "decided-by-user": false },
        { "cidr": "192.168.56.0/24", "kind": "virtual-machine", "adapter": "VirtualBox",
          "allowed": true, "decided-by-user": false }
    ]));
    let mut app = connected();
    if !app.settings.supports.local_network_exceptions {
        return;
    }
    check(&mut app);
    drain(&mut app, &fake);
    let texts = texts_en();
    announce(&mut app, &texts, Instant::now());
    announce(&mut app, &texts, Instant::now());

    assert_eq!(app.notices.len(), 1, "told once");
    let notice = &app.notices[0];
    assert_eq!(notice.title, "A local network was found");
    assert!(notice.body.contains("2001:db8:5:7::/64"), "{}", notice.body);
    assert!(notice.body.contains("Open them"), "{}", notice.body);
    assert!(notice.body.contains("1 more found"), "{}", notice.body);
    assert!(notice.body.contains("(c2)"), "{}", notice.body);
}

#[test]
fn nothing_waiting_says_nothing() {
    let fake = service(json!([
        { "cidr": "192.168.1.0/24", "kind": "main-link", "adapter": "Ethernet",
          "allowed": true, "decided-by-user": true }
    ]));
    let mut app = connected();
    check(&mut app);
    drain(&mut app, &fake);
    announce(&mut app, &texts_en(), Instant::now());
    assert!(app.notices.is_empty());
}

#[test]
fn every_key_is_in_both_locale_files() {
    let missing = crate::testing::missing_from_locales(&[
        keys::LOCAL_NETWORK_TITLE,
        keys::LOCAL_NETWORK_OFFER,
        keys::LOCAL_NETWORK_OFFER_OPEN,
        keys::LOCAL_NETWORK_OFFER_MORE,
        keys::ANSWER_IN_ROUTING_HINT,
    ]);
    assert!(missing.is_empty(), "{missing:?}");
}
