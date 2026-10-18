//! Blocks the service kept while no NetRuleRouter surface was open: read once
//! per connection, told as one notice, acknowledged so no other surface
//! repeats them — the same summary the window and the tray give.

use nrr_client_logic::block_notices::{backlog_summary, BacklogSummary};
use nrr_ipc_client::IpcClient;
use nrr_shared::display_text::display_text;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    BlockNoticeJournalAckRequest, BlockNoticeJournalAckResponse, BlockNoticeJournalListRequest,
    BlockNoticeJournalListResponse,
};

use crate::backend::{Job, Reply};
use crate::i18n::Texts;
use crate::keys;
use crate::screens::suggestions::call;
use crate::state::{AppState, Effect, NoticeLevel};

#[derive(Debug, Default)]
pub struct BlockBacklogState {
    loading: bool,
    /// Read but not yet told; announced on the next tick with texts in hand.
    unannounced: Option<BacklogSummary>,
}

/// Read the backlog. Called when the link comes up, after which live pushes
/// carry every new block.
pub fn drain(app: &mut AppState) {
    if !app.link.is_connected() || app.block_backlog.loading {
        return;
    }
    app.block_backlog.loading = true;
    app.outbox.push(list_job());
}

fn list_job() -> Job {
    Box::new(|client: &dyn IpcClient| {
        let answer: Result<BlockNoticeJournalListResponse, _> = call(
            client,
            IpcOperationName::BlockNoticeJournalList,
            &BlockNoticeJournalListRequest {},
        );
        Reply::new(move |app| {
            app.block_backlog.loading = false;
            let Some(summary) = answer.ok().and_then(|a| backlog_summary(&a.entries)) else {
                return;
            };
            if summary.through_id > 0 {
                app.outbox.push(ack_job(summary.through_id));
            }
            app.block_backlog.unannounced = Some(summary);
        })
    })
}

fn ack_job(through_id: i64) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        // A failed acknowledgement only means the summary comes again.
        let _: Result<BlockNoticeJournalAckResponse, _> = call(
            client,
            IpcOperationName::BlockNoticeJournalAck,
            &BlockNoticeJournalAckRequest { through_id },
        );
        Reply::new(|_| {})
    })
}

/// Tell the summary read last, once.
pub fn announce(app: &mut AppState, texts: &Texts, now: std::time::Instant) -> Vec<Effect> {
    let Some(summary) = app.block_backlog.unannounced.take() else {
        return Vec::new();
    };
    let mut body = texts.fill(
        keys::BLOCK_NOTICE_BACKLOG_BODY,
        &[("count", summary.count.to_string())],
    );
    if !summary.shown.is_empty() {
        let shown: Vec<_> = summary.shown.iter().map(|d| display_text(d)).collect();
        let mut list = shown.join(", ");
        if summary.more > 0 {
            list.push_str(", ");
            list.push_str(&texts.fill(
                keys::BLOCK_NOTICE_BACKLOG_MORE,
                &[("count", summary.more.to_string())],
            ));
        }
        body.push(' ');
        body.push_str(&texts.fill(keys::BLOCK_NOTICE_BACKLOG_DESTINATIONS, &[("list", list)]));
    }
    app.notify(
        NoticeLevel::Warning,
        texts.get(keys::BLOCK_NOTICE_BACKLOG_TITLE),
        body,
        now,
    )
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use nrr_ipc_client::ConnectionStatus;
    use nrr_shared::ipc::IpcOperationName;
    use serde_json::{json, Value};

    use crate::backend::BackendEvent;
    use crate::link::Link;
    use crate::screens::ScreenId;
    use crate::state::{AppState, NoticeLevel};
    use crate::testing::{texts_en, FakeService};

    const TITLE: &str = "Blocked while the app was closed";

    fn entry(id: i64, destination: &str) -> Value {
        json!({
            "id": id,
            "raised-at-unix-ms": 1,
            "destination": destination,
            "app": "",
            "reason": "route-unavailable",
            "attempts": 1
        })
    }

    /// Connect, then answer every job as the loop would, follow-ups included.
    fn connect(fake: &FakeService) -> AppState {
        let texts = texts_en();
        let mut app = AppState::new(ScreenId::Status, false);
        app.apply(BackendEvent::Link(Link::Connected), &texts, Instant::now());
        for _ in 0..4 {
            for job in app.outbox.take() {
                app.apply(BackendEvent::Reply(job(fake)), &texts, Instant::now());
            }
        }
        app
    }

    #[test]
    fn the_backlog_is_told_once_and_acknowledged_on_connect() {
        let fake = FakeService::new(ConnectionStatus::Connected);
        fake.answer(
            IpcOperationName::BlockNoticeJournalList,
            json!({ "entries": [
                entry(3, "203.0.113.7"),
                entry(8, "203.0.113.7"),
                entry(5, "cdn.example")
            ] }),
        );
        fake.answer(
            IpcOperationName::BlockNoticeJournalAck,
            json!({ "acknowledged": 3 }),
        );

        let app = connect(&fake);

        let told: Vec<_> = app.notices.iter().filter(|n| n.title == TITLE).collect();
        assert_eq!(told.len(), 1, "{:?}", app.notices);
        assert_eq!(told[0].level, NoticeLevel::Warning);
        assert_eq!(
            told[0].body,
            "The service blocked 3 connection(s) while NetRuleRouter was not open. \
             Destinations: 203.0.113.7, cdn.example."
        );
        assert_eq!(
            fake.sent(IpcOperationName::BlockNoticeJournalAck),
            vec![json!({ "through-id": 8 })]
        );
    }

    #[test]
    fn an_empty_backlog_says_nothing_and_acknowledges_nothing() {
        let fake = FakeService::new(ConnectionStatus::Connected);
        fake.answer(
            IpcOperationName::BlockNoticeJournalList,
            json!({ "entries": [] }),
        );

        let app = connect(&fake);

        assert!(app.notices.iter().all(|n| n.title != TITLE));
        assert!(fake
            .sent(IpcOperationName::BlockNoticeJournalAck)
            .is_empty());
    }

    #[test]
    fn a_service_without_the_backlog_is_not_an_error_on_screen() {
        let fake = FakeService::new(ConnectionStatus::Connected);

        let app = connect(&fake);

        assert!(app.notices.iter().all(|n| n.title != TITLE));
        assert!(
            !app.block_backlog.loading,
            "a failed read does not wedge the next one"
        );
    }
}
