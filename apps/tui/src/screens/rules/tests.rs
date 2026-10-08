#![allow(clippy::expect_used)]

use nrr_ipc_client::ConnectionStatus;
use nrr_shared::ipc::IpcOperationName;
use serde_json::json;

use super::{apply, text};
use crate::screens::ScreenId;
use crate::state::AppState;
use crate::testing::{missing_from_locales, texts_en, FakeService};

#[test]
fn every_key_is_in_both_locale_files() {
    let missing = missing_from_locales(text::ALL);
    assert!(missing.is_empty(), "{missing:?}");
}

/// Under `sudo` the screen writes the administrator's baseline and says so;
/// otherwise the caller's own rules, unmarked.
#[test]
fn under_root_the_rules_go_to_the_baseline_and_the_title_says_so() {
    let pending = |admin_baseline| apply::Pending {
        rules_json: "{}".into(),
        content_hash: "h".into(),
        correlation_id: "c".into(),
        admin_baseline,
    };
    for baseline in [true, false] {
        let fake = FakeService::new(ConnectionStatus::Connected);
        fake.answer(
            IpcOperationName::MutationSubmit,
            json!({ "confirmation-token": "t", "review-summary": {} }),
        );
        let mut app = AppState::new(ScreenId::Rules, false);
        let reply = apply::preview_job(pending(baseline))(&fake);
        (reply.0)(&mut app);
        let sent = fake.sent(IpcOperationName::MutationSubmit);
        assert_eq!(
            sent[0]["payload"]
                .get("admin-baseline")
                .and_then(|v| v.as_bool()),
            baseline.then_some(true),
            "{sent:?}"
        );
    }

    let texts = texts_en();
    let mut app = AppState::new(ScreenId::Rules, false);
    app.rules.baseline = true;
    let view = super::render::view(&app, &texts);
    assert_eq!(view.title, texts.get(text::TITLE_BASELINE));
}
