//! "Confirm your main connection" — the terminal UI's answer to the service
//! naming the one connection the route table points at, for a user who bound
//! none.
//!
//! The Status screen shows the notice; `p` binds that connection as main, the
//! same write the tray's Confirm makes; choosing another is the Interfaces
//! screen. Which row the name means is decided in `nrr-client-logic`, so both
//! clients bind the same adapter or neither does.

use nrr_client_logic::adapters::suggested_primary_binding;
use nrr_client_logic::Route;

use crate::i18n::{key, Key, Texts};
use crate::screens::binding::{role_label, role_write, RoleChange, WriteFailure};
use crate::screens::interfaces::keys as k;
use crate::state::{AppState, Effect, NoticeLevel};

pub const HELP: Key = key(
    "tui.help.status-confirm-primary",
    "p: confirm the suggested main connection; another one is chosen under Connections",
);

pub const AMBIGUOUS: Key = key(
    "tui.status.primary-suggestion-ambiguous",
    "No single connection answers to that name now. Choose the main connection under Connections.",
);

/// Between the key and the service's answer.
#[derive(Debug, Default)]
pub struct PrimarySuggestionState {
    pub busy: bool,
    unannounced: Option<Outcome>,
}

#[derive(Debug)]
enum Outcome {
    Bound(RoleChange),
    Failed(WriteFailure),
    Ambiguous,
}

/// The connection the standing no-policy report offers, when it offers one.
pub fn suggested(app: &AppState) -> Option<&str> {
    let down = app.enforcement_down.get("")?;
    (down.status == "no-policy")
        .then(|| down.candidates.first().map(String::as_str))
        .flatten()
}

/// Bind the suggested connection as main. `false` when nothing is suggested,
/// the service is away or a write is in flight.
pub fn confirm(app: &mut AppState) -> bool {
    if app.primary_suggestion.busy || !app.link.is_connected() {
        return false;
    }
    let Some(name) = suggested(app).map(str::to_owned) else {
        return false;
    };
    let rows = app
        .snapshot
        .as_ref()
        .map(|s| s.adapters.rows.as_slice())
        .unwrap_or_default();
    let Some(binding) = suggested_primary_binding(rows, &name) else {
        app.primary_suggestion.unannounced = Some(Outcome::Ambiguous);
        return true;
    };
    let change = RoleChange::Assign {
        route: Route::Primary,
        stable_id: binding.stable_id,
        name: binding.display_name,
    };
    app.primary_suggestion.busy = true;
    app.outbox.push(role_write(change, |app, change, result| {
        app.primary_suggestion.busy = false;
        app.primary_suggestion.unannounced = Some(match result {
            Ok(()) => Outcome::Bound(change.clone()),
            Err(failure) => Outcome::Failed(failure),
        });
    }));
    true
}

/// Say how the last confirmation went, once texts are in hand.
pub fn announce(app: &mut AppState, texts: &Texts, now: std::time::Instant) -> Vec<Effect> {
    let Some(outcome) = app.primary_suggestion.unannounced.take() else {
        return Vec::new();
    };
    let title = texts.get(role_label(Route::Primary));
    match outcome {
        Outcome::Bound(change) => {
            app.notify(NoticeLevel::Info, title, change.done_text(texts), now)
        }
        Outcome::Failed(failure) => app.notify(
            NoticeLevel::Warning,
            title,
            failure.text(k::BINDING_FAILED, texts),
            now,
        ),
        Outcome::Ambiguous => app.notify(NoticeLevel::Warning, title, texts.get(AMBIGUOUS), now),
    }
}
