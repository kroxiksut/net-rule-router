//! "Is this your VPN?" — the terminal UI's answer to a program named like a
//! VPN client that leak protection does not trust by place.
//!
//! The Status screen lists the service's pending clients; `t` confirms every
//! one of them, each with the programs of its own protected install tree, by
//! replacing the link provider set with what was confirmed before plus the
//! answer — the same decision the window makes, from `nrr-client-logic`.

use nrr_client_logic::vpn_client_trust::{
    confirmed_apps, trust_offers, LinkProviderApp, TrustOffer,
};
use nrr_ipc_client::IpcClient;
use nrr_shared::display_text::display_text;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    LinkProviderAppDto, PendingVpnClientDto, RouteLinkProviderSetRequest,
    RouteLinkProviderSetResponse,
};

use crate::backend::{Job, Reply};
use crate::i18n::{key, Key, Texts};
use crate::keys;
use crate::screens::suggestions::call;
use crate::state::{AppState, Effect, NoticeLevel};

pub const HELP: Key = key(
    "tui.help.status-vpn-trust",
    "t: confirm the listed programs as your VPN, so leak protection keeps them working",
);

/// What the TUI keeps between the service's list and the user's key.
#[derive(Debug, Default)]
pub struct VpnTrustState {
    /// The service's pending clients, from the snapshot or the last push.
    pub pending: Vec<PendingVpnClientDto>,
    pub busy: bool,
    /// The last write's outcome, announced on the next tick with texts in hand.
    unannounced: Option<Result<usize, String>>,
}

/// One question per pending program, as the window asks them.
pub fn offers(pending: &[PendingVpnClientDto]) -> Vec<TrustOffer> {
    let pairs: Vec<(String, Vec<String>)> = pending
        .iter()
        .map(|c| (c.exe_path.clone(), c.bundled_exe_paths.clone()))
        .collect();
    trust_offers(&pairs)
}

/// The names the Status screen lists, ready to show.
pub fn names(pending: &[PendingVpnClientDto]) -> Vec<String> {
    offers(pending)
        .into_iter()
        .map(|o| display_text(&o.name).into_owned())
        .collect()
}

/// Confirm every pending program, bundles included. `false` when there is
/// nothing to confirm, the service is away or a write is in flight.
pub fn trust_pending(app: &mut AppState) -> bool {
    if app.vpn_trust.pending.is_empty() || app.vpn_trust.busy || !app.link.is_connected() {
        return false;
    }
    let mut apps: Vec<LinkProviderApp> = app
        .snapshot
        .as_ref()
        .and_then(|s| s.route_policy.as_ref())
        .map(|policy| {
            policy
                .secondary_link_provider_apps
                .iter()
                .map(|a| LinkProviderApp {
                    exe_path: a.exe_path.clone(),
                    display_name: a.display_name.clone(),
                })
                .collect()
        })
        .unwrap_or_default();
    for offer in offers(&app.vpn_trust.pending) {
        apps = confirmed_apps(&apps, &offer, true);
    }
    let confirmed = app.vpn_trust.pending.len();
    let request = RouteLinkProviderSetRequest {
        role: "secondary".to_string(),
        link_provider_apps: apps
            .into_iter()
            .map(|a| LinkProviderAppDto {
                exe_path: a.exe_path,
                display_name: a.display_name,
            })
            .collect(),
    };
    app.vpn_trust.busy = true;
    app.outbox.push(trust_job(request, confirmed));
    true
}

fn trust_job(request: RouteLinkProviderSetRequest, confirmed: usize) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let result: Result<RouteLinkProviderSetResponse, _> =
            call(client, IpcOperationName::RouteLinkProviderSet, &request);
        Reply::new(move |app| {
            app.vpn_trust.busy = false;
            app.vpn_trust.unannounced = Some(match result {
                Ok(_) => {
                    // The service republishes its list on the next compute;
                    // until then the question is answered.
                    app.vpn_trust.pending.clear();
                    Ok(confirmed)
                }
                Err(error) => Err(error.message),
            });
        })
    })
}

/// Say how the last write went, once texts are in hand.
pub fn announce(app: &mut AppState, texts: &Texts, now: std::time::Instant) -> Vec<Effect> {
    let Some(outcome) = app.vpn_trust.unannounced.take() else {
        return Vec::new();
    };
    match outcome {
        Ok(count) => app.notify(
            NoticeLevel::Info,
            texts.get(keys::VPN_TRUST_TITLE),
            texts.fill(keys::VPN_TRUST_DONE, &[("count", count.to_string())]),
            now,
        ),
        Err(error) => app.notify(
            NoticeLevel::Warning,
            texts.get(keys::VPN_TRUST_TITLE),
            texts.fill(keys::VPN_TRUST_FAILED, &[("error", error)]),
            now,
        ),
    }
}
