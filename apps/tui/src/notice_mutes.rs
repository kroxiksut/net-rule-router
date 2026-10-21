//! The notice kinds the user silenced, as the service keeps them for every
//! surface: read when the link comes up and again whenever they change, and
//! asked before a notice of such a kind reaches the feed (the window's
//! `noticeKindMuted`). Until the first read answers nothing is silenced.

use nrr_client_logic::notice_mutes::notice_kind_muted;
use nrr_ipc_client::IpcClient;
use nrr_shared::ipc::IpcOperationName;
use serde_json::{json, Value};

use crate::backend::Reply;
use crate::screens::suggestions::call;
use crate::state::AppState;

#[derive(Debug, Default)]
pub struct NoticeMutesState {
    /// The `mutes` array of the last answer; anything else silences nothing.
    mutes: Value,
}

/// Read the mutes again. A failed read keeps the last list.
pub fn load(app: &mut AppState) {
    if !app.link.is_connected() {
        return;
    }
    app.outbox.push(Box::new(|client: &dyn IpcClient| {
        let answer: Result<Value, _> =
            call(client, IpcOperationName::BlockNoticeMutesList, &json!({}));
        Reply::new(move |app| {
            if let Some(mutes) = answer.ok().and_then(|a| a.get("mutes").cloned()) {
                app.notice_mutes.mutes = mutes;
            }
        })
    }));
}

/// Whether notices of `kind` are silenced now.
pub fn muted(app: &AppState, kind: &str) -> bool {
    notice_kind_muted(
        &app.notice_mutes.mutes,
        kind,
        chrono::Utc::now().timestamp_millis(),
    )
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use nrr_ipc_client::ConnectionStatus;
    use nrr_shared::ipc_payloads::StatusUpdateEvent;

    use super::*;
    use crate::backend::{BackendEvent, PushEvent};
    use crate::link::Link;
    use crate::screens::suggestions::tests::drain;
    use crate::screens::ScreenId;
    use crate::testing::{texts_en, FakeService};

    fn tunnel_found() -> BackendEvent {
        BackendEvent::Push(PushEvent::Status(Box::new(
            StatusUpdateEvent::UnassignedTunnelDetected {
                sid: "S".into(),
                adapter_name: "Example Tunnel".into(),
            },
        )))
    }

    fn connected(mutes: Value) -> (AppState, FakeService) {
        let fake = FakeService::new(ConnectionStatus::Connected);
        fake.answer(
            IpcOperationName::BlockNoticeMutesList,
            json!({ "mutes": mutes }),
        );
        let mut app = AppState::new(ScreenId::Status, false);
        app.apply(
            BackendEvent::Link(Link::Connected),
            &texts_en(),
            Instant::now(),
        );
        drain(&mut app, &fake);
        (app, fake)
    }

    #[test]
    fn a_silenced_kind_stays_out_of_the_feed() {
        let (mut app, fake) = connected(json!([
            { "scope": { "kind": "notice", "notice": "unassigned-tunnel" } }
        ]));
        let before = app.notice_count;
        app.apply(tunnel_found(), &texts_en(), Instant::now());
        assert_eq!(app.notice_count, before);

        // Lifted on another surface: the change is read and the next one told.
        fake.answer(
            IpcOperationName::BlockNoticeMutesList,
            json!({ "mutes": [] }),
        );
        app.apply(
            BackendEvent::Push(PushEvent::Status(Box::new(
                StatusUpdateEvent::BlockNoticeMutesChanged { sid: "S".into() },
            ))),
            &texts_en(),
            Instant::now(),
        );
        drain(&mut app, &fake);
        app.apply(tunnel_found(), &texts_en(), Instant::now());
        assert_eq!(app.notice_count, before + 1);
    }

    #[test]
    fn a_mute_that_ran_out_or_names_another_kind_silences_nothing() {
        let (mut app, _) = connected(json!([
            { "scope": { "kind": "notice", "notice": "unassigned-tunnel" }, "until-unix-ms": 1 },
            { "scope": { "kind": "notice", "notice": "external-address" } }
        ]));
        let before = app.notice_count;
        app.apply(tunnel_found(), &texts_en(), Instant::now());
        assert_eq!(app.notice_count, before + 1);
    }
}
