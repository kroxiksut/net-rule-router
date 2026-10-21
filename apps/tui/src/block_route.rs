//! "To additional route" — the tray's answer to a block notice, in the
//! terminal UI. A block a rule can answer (the decision is the tray's, from
//! `nrr-client-logic`) is offered under the state on the Status screen; `v`
//! asks first, as the tray does, and `y` has the service write the rule.
//! The bound rules files then follow, as after an accepted suggestion.

use nrr_client_logic::block_notices::offers_route;
use nrr_ipc_client::IpcClient;
use nrr_shared::display_text::display_text;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    BlockNoticeRouteToSecondaryRequest, BlockNoticeRouteToSecondaryResponse,
};

use crate::backend::{Job, Reply};
use crate::i18n::{key, Key, Texts};
use crate::screens::suggestions::{call, CallError};
use crate::state::{AppState, Effect, NoticeLevel};

/// Destinations kept on offer, as many as the tray's notice lists.
const OFFERED_CAP: usize = 5;
/// Longer than any hostname, trailing dot included: nothing to route by.
const DESTINATION_MAX: usize = 254;

pub const ACTION: Key = key(
    "tray.block-notice.action.route-to-secondary",
    "To additional route",
);
pub const OFFER: Key = key(
    "tui.status.block-route-offer",
    "{name} was blocked. v: send it over the additional route.",
);
pub const MORE: Key = key(
    "tui.status.block-route-more",
    "Blocked sites waiting after it: {count}.",
);
pub const ASK: Key = key(
    "tray.block-notice.route-confirm.title",
    "Route {name} via the additional link?",
);
pub const ASK_BODY: Key = key(
    "tray.block-notice.route-confirm.body",
    "Adds a rule that sends this address over the additional route from now on. You can undo it later in Rules.",
);
pub const YES_NO: Key = key("tui.list.yes-no", "y: yes   n: no");
pub const DONE: Key = key(
    "tui.status.block-route-done",
    "{name} now goes over the additional route. You can undo it in Rules.",
);
pub const ALREADY: Key = key(
    "tui.status.block-route-already",
    "{name} already goes over the additional route; nothing was added.",
);
pub const FAILED: Key = key(
    "tui.status.block-route-failed",
    "Could not send {name} over the additional route: {error}",
);
pub const HELP: Key = key(
    "tui.help.status-block-route",
    "v: send the blocked site named under the state over the additional route; you are asked first",
);

#[cfg(test)]
pub fn keys() -> Vec<Key> {
    vec![
        ACTION, OFFER, MORE, ASK, ASK_BODY, YES_NO, DONE, ALREADY, FAILED, HELP,
    ]
}

#[derive(Debug, Default)]
pub struct BlockRouteState {
    /// Destinations on offer, newest first, each once.
    pub offered: Vec<String>,
    /// What `v` asked about, until it is answered.
    pub asking: Option<String>,
    pub busy: bool,
    /// The last write's destination and outcome (`true`: a rule was added),
    /// announced on the next tick with texts in hand.
    unannounced: Option<(String, Result<bool, CallError>)>,
}

/// A block notice arrived: its destination goes on offer when a rule routing
/// it could answer the block.
pub fn offer(app: &mut AppState, destination: &str, reason: &str) {
    let destination = destination.trim();
    if destination.is_empty() || destination.len() > DESTINATION_MAX || !offers_route(reason) {
        return;
    }
    let offered = &mut app.block_route.offered;
    offered.retain(|d| d != destination);
    offered.insert(0, destination.to_owned());
    offered.truncate(OFFERED_CAP);
}

/// Whether the question `v` asked waits for its answer.
pub fn asking(app: &AppState) -> bool {
    app.block_route.asking.is_some()
}

/// `v`: ask about the newest destination on offer. `false` when nothing is
/// offered, the service is away, or a question or a write is open.
pub fn ask(app: &mut AppState) -> bool {
    let state = &mut app.block_route;
    if state.busy || state.asking.is_some() || !app.link.is_connected() {
        return false;
    }
    let Some(first) = state.offered.first().cloned() else {
        return false;
    };
    state.asking = Some(first);
    true
}

/// The answer to the question. Either way the offer is answered, as the
/// tray's notice closes on Confirm and on Cancel.
pub fn answer(app: &mut AppState, yes: bool) -> bool {
    let Some(destination) = app.block_route.asking.take() else {
        return false;
    };
    if yes && !app.link.is_connected() {
        return true;
    }
    app.block_route.offered.retain(|d| *d != destination);
    if yes {
        app.block_route.busy = true;
        app.outbox.push(route_job(destination));
    }
    true
}

fn route_job(destination: String) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let answer: Result<BlockNoticeRouteToSecondaryResponse, _> = call(
            client,
            IpcOperationName::BlockNoticeRouteToSecondary,
            &BlockNoticeRouteToSecondaryRequest {
                destination: destination.clone(),
            },
        );
        Reply::new(move |app| {
            app.block_route.busy = false;
            let authored = answer.map(|a| a.authored);
            if matches!(authored, Ok(true)) {
                crate::screens::rules::rules_written_for_an_answer(app);
            }
            app.block_route.unannounced = Some((destination, authored));
        })
    })
}

/// The lines under the state: the offer, or the question it led to.
pub fn lines(app: &AppState, texts: &Texts) -> Vec<String> {
    if !app.link.is_connected() {
        return Vec::new();
    }
    let state = &app.block_route;
    if let Some(destination) = &state.asking {
        let name = display_text(destination).into_owned();
        return vec![
            texts.fill(ASK, &[("name", name)]),
            texts.get(ASK_BODY),
            texts.get(YES_NO),
        ];
    }
    let Some(first) = state.offered.first() else {
        return Vec::new();
    };
    let mut lines = vec![texts.fill(OFFER, &[("name", display_text(first).into_owned())])];
    if state.offered.len() > 1 {
        lines.push(texts.fill(MORE, &[("count", (state.offered.len() - 1).to_string())]));
    }
    lines
}

/// Say how the last write went, once texts are in hand.
pub fn announce(app: &mut AppState, texts: &Texts, now: std::time::Instant) -> Vec<Effect> {
    let Some((destination, outcome)) = app.block_route.unannounced.take() else {
        return Vec::new();
    };
    let name = display_text(&destination).into_owned();
    let (level, body) = match outcome {
        Ok(true) => (NoticeLevel::Info, texts.fill(DONE, &[("name", name)])),
        Ok(false) => (NoticeLevel::Info, texts.fill(ALREADY, &[("name", name)])),
        Err(error) => (
            NoticeLevel::Warning,
            texts.fill(FAILED, &[("name", name), ("error", error.text(texts))]),
        ),
    };
    app.notify(level, texts.get(ACTION), body, now)
}

#[cfg(test)]
mod tests;
