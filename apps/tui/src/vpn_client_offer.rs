//! "Is this your VPN?" when the additional link comes up and no VPN client is
//! set: the running programs tied by name to its adapter are told on the feed,
//! as the window raises its card, and answered in Settings → Routing, where
//! the same programs are offered as one row. Never confirmed silently: a wrong
//! guess would let a program past leak protection.

use nrr_client_logic::vpn_client_trust::{picker_link_offer, LinkClientOffer, PickerRow};
use nrr_ipc_client::IpcClient;
use nrr_shared::display_text::display_text;

use crate::backend::Reply;
use crate::i18n::{key, Key, Texts};
use crate::keys;
use crate::state::{AppState, Effect, NoticeLevel};

pub const TITLE: Key = key("notifications.vpn-client-trust.title", "Is this your VPN?");
pub const BODY: Key = key(
    "notifications.vpn-client-offer.body",
    "Looks like your VPN is {name}. Use it as your VPN client, so it keeps working over your main connection while leak protection is on? Programs: {apps}",
);

#[derive(Debug, Default)]
pub struct VpnClientOfferState {
    scanning: bool,
    /// Adapter names already asked about this run.
    asked: Vec<String>,
    unannounced: Option<LinkClientOffer>,
}

/// The bound additional adapter's name while no VPN client is set.
fn unset_link(app: &AppState) -> Option<String> {
    let policy = app.snapshot.as_ref()?.route_policy.as_ref()?;
    if !policy.secondary_link_provider_apps.is_empty() {
        return None;
    }
    let name = policy.secondary.as_ref()?.display_name.trim().to_owned();
    (!name.is_empty()).then_some(name)
}

/// Look for the link's client. Called when the additional link comes up.
pub fn check(app: &mut AppState) {
    if app.vpn_client_offer.scanning || !app.link.is_connected() {
        return;
    }
    let Some(link) = unset_link(app) else {
        return;
    };
    if app.vpn_client_offer.asked.contains(&link) {
        return;
    }
    app.vpn_client_offer.scanning = true;
    app.outbox.push(Box::new(move |_client: &dyn IpcClient| {
        let rows = crate::screens::settings::found_rows(
            &crate::platform::vpn_discovery().discover_vpn_candidates(),
        );
        Reply::new(move |app| {
            app.vpn_client_offer.scanning = false;
            found(app, &link, rows);
        })
    }));
}

/// What the scan found for `link`. The rows also fill the Settings list, so
/// the answer the notice points at is already on screen there.
pub fn found(app: &mut AppState, link: &str, rows: Vec<PickerRow>) {
    if unset_link(app).as_deref() != Some(link) {
        return;
    }
    app.vpn_client_offer.asked.push(link.to_owned());
    let offer = picker_link_offer(&rows, link);
    if offer.exe_paths.is_empty() {
        return;
    }
    app.settings.providers.found = Some(rows);
    app.vpn_client_offer.unannounced = Some(offer);
}

/// Tell the offer found last, once.
pub fn announce(app: &mut AppState, texts: &Texts, now: std::time::Instant) -> Vec<Effect> {
    let Some(offer) = app.vpn_client_offer.unannounced.take() else {
        return Vec::new();
    };
    let apps: Vec<String> = offer
        .exe_paths
        .iter()
        .map(|p| display_text(nrr_client_logic::vpn_gateway::program_file_name(p)).into_owned())
        .collect();
    let mut body = texts.fill(
        BODY,
        &[
            ("name", display_text(&offer.name).into_owned()),
            ("apps", apps.join(", ")),
        ],
    );
    body.push(' ');
    body.push_str(&texts.get(keys::ANSWER_IN_ROUTING_HINT));
    app.notify(NoticeLevel::Info, texts.get(TITLE), body, now)
}

#[cfg(test)]
mod tests;
