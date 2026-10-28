//! Virtual machines, emulators and peer-to-peer programs found on this
//! computer, told on the feed once, as the window's banner offers them: a
//! hypervisor installed long before this program is otherwise never noticed.
//! The feed cannot be answered, so the telling is remembered in the terminal's
//! own settings and the App groups screen keeps the list.

use nrr_ipc_client::IpcClient;
use nrr_platform_api::app_group_discovery::{AppGroupKind, DiscoveredApp};
use nrr_shared::display_text::display_text;

use crate::backend::{Job, Reply};
use crate::i18n::{key, Key, Texts};
use crate::state::{AppState, Effect, NoticeLevel};

pub const OFFER: Key = key(
    "status.app-groups-offer",
    "Found programs that can be given their own route: {names}.",
);
pub const MORE: Key = key("status.local-network-offer-more", "{count} more found.");
pub const TITLE: Key = key("app-groups.title", "Application and device routes");
pub const HOW: Key = key(
    "tui.app-groups-offer.how",
    "To give them a route, press g on the Rules screen.",
);

/// Names told in the sentence; the rest are counted.
const NAMED: usize = 3;

#[derive(Debug)]
pub struct AppGroupsOfferState {
    started: bool,
    /// What the look found, not yet told.
    unannounced: Option<Vec<String>>,
    /// The machine's scan; a test hands in its own.
    pub discover: fn() -> Vec<DiscoveredApp>,
}

impl Default for AppGroupsOfferState {
    fn default() -> Self {
        Self {
            started: false,
            unannounced: None,
            discover: DISCOVER,
        }
    }
}

#[cfg(not(test))]
const DISCOVER: fn() -> Vec<DiscoveredApp> = scan_this_machine;
/// Tests never scan the machine they run on.
#[cfg(test)]
const DISCOVER: fn() -> Vec<DiscoveredApp> = Vec::new;

#[cfg(not(test))]
fn scan_this_machine() -> Vec<DiscoveredApp> {
    crate::platform::app_group_discovery().discover_app_groups()
}

/// Look once a run, unless the offer was told before.
pub fn check(app: &mut AppState) {
    if app.app_groups_offer.started || app.settings.prefs.app_groups_offer_told {
        return;
    }
    app.app_groups_offer.started = true;
    app.outbox.push(look_job(app.app_groups_offer.discover));
}

fn look_job(discover: fn() -> Vec<DiscoveredApp>) -> Job {
    Box::new(move |_client: &dyn IpcClient| {
        let found = offered(&discover());
        Reply::new(move |app| app.app_groups_offer.unannounced = Some(found))
    })
}

/// A kernel virtual network has no program to route: listed on the screen,
/// no reason to ask.
fn offered(apps: &[DiscoveredApp]) -> Vec<String> {
    apps.iter()
        .filter(|app| app.kind != AppGroupKind::KernelVirtualNet)
        .map(|app| display_text(&app.display_name).into_owned())
        .collect()
}

/// Tell what was found, once ever.
pub fn announce(app: &mut AppState, texts: &Texts, _now: std::time::Instant) -> Vec<Effect> {
    let Some(found) = app.app_groups_offer.unannounced.take() else {
        return Vec::new();
    };
    if found.is_empty() {
        return Vec::new();
    }
    let names: Vec<&str> = found.iter().take(NAMED).map(String::as_str).collect();
    let mut body = texts.fill(OFFER, &[("names", names.join(", "))]);
    if found.len() > NAMED {
        body.push(' ');
        body.push_str(&texts.fill(MORE, &[("count", (found.len() - NAMED).to_string())]));
    }
    body.push(' ');
    body.push_str(&texts.get(HOW));
    app.settings.prefs.app_groups_offer_told = true;
    // Unsaved, the offer comes back next run: a repeat, not a loss.
    let _ = app.settings.save_prefs();
    // News for when the user looks, not worth a bell.
    app.note_in_feed(NoticeLevel::Info, texts.get(TITLE), body)
}

#[cfg(test)]
mod tests;
