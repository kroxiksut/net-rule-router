//! Changes the window made while the service was not running and still holds
//! for it. They live in the window, which sends them when it next connects; the
//! terminal only says they wait, so a user here does not take the service's
//! state for the whole story.

use std::path::Path;

use nrr_shared::user_settings::{UserSettings, UserSettingsStore};
use serde_json::{Map, Value};

use crate::i18n::{key, Key, Texts};
use crate::state::AppState;
use crate::view::{Segment, StateTone, ViewLine};

pub const WAITING: Key = key(
    "tui.status.window-parked",
    "The window holds changes made while the service was not running: {what}. It sends them when it next connects to the service.",
);
pub const ROUTING: Key = key(
    "tui.status.window-parked-routing",
    "routing settings: {count}",
);
pub const SERVICE: Key = key(
    "tui.status.window-parked-service",
    "service settings: {count}",
);
pub const ROLES: Key = key("tui.status.window-parked-roles", "adapter roles");

/// What waits in the window, counted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WindowParked {
    pub routing: usize,
    pub service: usize,
    pub roles: bool,
}

impl WindowParked {
    fn is_empty(&self) -> bool {
        self.routing == 0 && self.service == 0 && !self.roles
    }
}

/// Read again from the settings file both clients share; a file that cannot
/// be read shows nothing rather than a guess.
pub fn refresh(app: &mut AppState) {
    let settings = app.rules.settings_file.as_deref().and_then(read);
    app.window_parked = settings.and_then(|s| parked(&s.window_parked, now_ms()));
}

fn read(file: &Path) -> Option<UserSettings> {
    UserSettingsStore::at(file.to_path_buf())
        .load()
        .ok()
        .flatten()
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// The window drops what it parked past its age limit; so does this line.
pub fn parked(blob: &Map<String, Value>, now_ms: i64) -> Option<WindowParked> {
    if blob.is_empty()
        || nrr_shared::parked_intents_expired(&Value::Object(blob.clone()).to_string(), now_ms)
    {
        return None;
    }
    let count = |namespace: &str| {
        blob.get(namespace)
            .and_then(Value::as_object)
            .map_or(0, Map::len)
    };
    let summary = WindowParked {
        routing: count("route-policy"),
        service: count("stability"),
        roles: count("binding") > 0,
    };
    (!summary.is_empty()).then_some(summary)
}

pub fn lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let Some(parked) = &app.window_parked else {
        return Vec::new();
    };
    let mut what = Vec::new();
    if parked.routing > 0 {
        what.push(texts.fill(ROUTING, &[("count", parked.routing.to_string())]));
    }
    if parked.service > 0 {
        what.push(texts.fill(SERVICE, &[("count", parked.service.to_string())]));
    }
    if parked.roles {
        what.push(texts.get(ROLES));
    }
    vec![ViewLine::new(vec![Segment::state(
        texts.fill(WAITING, &[("what", what.join(", "))]),
        StateTone::Caution,
    )])]
}

#[cfg(test)]
mod tests;
