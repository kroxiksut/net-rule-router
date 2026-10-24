//! "Let this VPN connect?" — the terminal UI's answer when leak protection
//! stopped another VPN reaching its server over the main link.
//!
//! The Status screen lists the service's pending gateways; `a` allows the
//! first, the next is asked after it. The write replaces the caller's whole list, so it starts from
//! a fresh read of what the service holds and adds the answer with the same
//! decision the window makes, from `nrr-client-logic`.

use nrr_client_logic::vpn_gateway_trust::{
    confirmed_gateways, gateway_offers, Gateway, GatewayOffer,
};
use nrr_ipc_client::{ipc_error_to_wire, ipc_operation_timeout, IpcClient, IpcClientError};
use nrr_shared::display_text::display_text;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    RouteVpnGatewaysSetRequest, RouteVpnGatewaysSetResponse, VpnGatewayDto,
};
use serde_json::json;

use crate::backend::{Job, Reply};
use crate::i18n::{key, Key, Texts};
use crate::keys;
use crate::state::{AppState, Effect, NoticeLevel};

pub const TITLE: Key = key(
    "notifications.vpn-gateway-trust.title",
    "Let this VPN connect?",
);
pub const BODY: Key = key(
    "notifications.vpn-gateway-trust.body",
    "Leak protection stopped a VPN from reaching its server {address} over your main connection. Allow it and that VPN connects while leak protection is on; nothing else is let through to that address.",
);
pub const BODY_PROGRAM: Key = key(
    "notifications.vpn-gateway-trust.body-program",
    "Leak protection stopped {name} from reaching the VPN server {address} over your main connection. Allow it and that VPN connects while leak protection is on; nothing else is let through to that address.",
);
pub const ALLOWED: Key = key(
    "vpn-onboarding.gateway-allowed-status",
    "The VPN server {address} can now be reached while leak protection is on.",
);
pub const ALLOWED_MANY: Key = key(
    "tui.status.vpn-gateway-allowed-many",
    "The VPN servers {addresses} can now be reached while leak protection is on.",
);
pub const HINT: Key = key(
    "tui.status.vpn-gateway-hint",
    "a: allow the first VPN listed to reach its server while leak protection is on. The others are asked one at a time after it.",
);
pub const HELP: Key = key(
    "tui.help.status-vpn-gateway",
    "a: allow the first listed VPN to reach its server, so leak protection lets it connect",
);

#[cfg(test)]
pub fn keys() -> Vec<Key> {
    vec![TITLE, BODY, BODY_PROGRAM, ALLOWED, ALLOWED_MANY, HINT, HELP]
}

/// What the TUI keeps between the service's lists and the user's key.
#[derive(Debug, Default)]
pub struct VpnGatewayTrustState {
    /// The service's pending gateways, from the snapshot or the last push.
    pub pending: Vec<VpnGatewayDto>,
    /// The gateways the user let through, from the snapshot or the last write.
    pub confirmed: Vec<VpnGatewayDto>,
    pub busy: bool,
    /// The last write's outcome (the addresses allowed, or the error),
    /// announced on the next tick with texts in hand.
    unannounced: Option<Result<Vec<String>, String>>,
}

fn gateway(dto: &VpnGatewayDto) -> Gateway {
    Gateway {
        address: dto.address.clone(),
        program: dto.program.clone(),
    }
}

/// One question per pending address, as the window asks them.
pub fn offers(pending: &[VpnGatewayDto]) -> Vec<GatewayOffer> {
    let gateways: Vec<Gateway> = pending.iter().map(gateway).collect();
    gateway_offers(&gateways)
}

/// One sentence per pending gateway, ready to show.
pub fn sentences(pending: &[VpnGatewayDto], texts: &Texts) -> Vec<String> {
    offers(pending)
        .iter()
        .map(|offer| {
            let address = display_text(&offer.address).into_owned();
            if offer.name.is_empty() {
                texts.fill(BODY, &[("address", address)])
            } else {
                let name = display_text(&offer.name).into_owned();
                texts.fill(BODY_PROGRAM, &[("name", name), ("address", address)])
            }
        })
        .collect()
}

/// The caller's confirmed list with `change` applied to what the service
/// holds now, written back; the stored list comes back.
pub fn rewrite(
    client: &dyn IpcClient,
    change: impl FnOnce(&[Gateway]) -> Vec<Gateway>,
) -> Result<Vec<VpnGatewayDto>, IpcClientError> {
    let snapshot = client.call(
        IpcOperationName::SnapshotInitialGet,
        json!({}),
        ipc_operation_timeout(IpcOperationName::SnapshotInitialGet),
    )?;
    let stored: Vec<VpnGatewayDto> = match snapshot.get("confirmed-vpn-gateways") {
        Some(list) => {
            serde_json::from_value(list.clone()).map_err(|e| IpcClientError::BadResponse {
                reason: e.to_string(),
            })?
        }
        None => Vec::new(),
    };
    let existing: Vec<Gateway> = stored.iter().map(gateway).collect();
    let request = RouteVpnGatewaysSetRequest {
        gateways: change(&existing)
            .into_iter()
            .map(|g| VpnGatewayDto {
                address: g.address,
                program: g.program,
            })
            .collect(),
    };
    let payload = serde_json::to_value(&request)
        .map_err(|e| IpcClientError::SerializationFailed(e.to_string()))?;
    let answer = client.call(
        IpcOperationName::RouteVpnGatewaysSet,
        payload,
        ipc_operation_timeout(IpcOperationName::RouteVpnGatewaysSet),
    )?;
    let response: RouteVpnGatewaysSetResponse =
        serde_json::from_value(answer).map_err(|e| IpcClientError::BadResponse {
            reason: e.to_string(),
        })?;
    Ok(response.gateways)
}

/// Allow the first pending gateway, as the window asks each address. `false`
/// when there is nothing to allow, the service is away or a write is in
/// flight.
pub fn allow_first(app: &mut AppState) -> bool {
    let state = &app.vpn_gateway_trust;
    if state.busy || !app.link.is_connected() {
        return false;
    }
    let Some(offer) = offers(&state.pending).into_iter().next() else {
        return false;
    };
    app.vpn_gateway_trust.busy = true;
    app.outbox.push(allow_job(offer));
    true
}

fn allow_job(offer: GatewayOffer) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let result = rewrite(client, |existing| confirmed_gateways(existing, &offer));
        Reply::new(move |app| {
            let state = &mut app.vpn_gateway_trust;
            state.busy = false;
            state.unannounced = Some(match result {
                Ok(stored) => {
                    state.confirmed = stored;
                    // The service republishes its list on the next compute;
                    // until then this question is answered and the next is up.
                    let address = offer.address.as_str();
                    state
                        .pending
                        .retain(|g| !g.address.trim().eq_ignore_ascii_case(address));
                    Ok(vec![offer.address])
                }
                Err(error) => Err(ipc_error_to_wire(&error).1),
            });
        })
    })
}

/// Say how the last write went, once texts are in hand.
pub fn announce(app: &mut AppState, texts: &Texts, now: std::time::Instant) -> Vec<Effect> {
    let Some(outcome) = app.vpn_gateway_trust.unannounced.take() else {
        return Vec::new();
    };
    match outcome {
        Ok(addresses) => {
            let shown: Vec<String> = addresses
                .iter()
                .map(|a| display_text(a).into_owned())
                .collect();
            let body = match shown.as_slice() {
                [one] => texts.fill(ALLOWED, &[("address", one.as_str())]),
                many => texts.fill(ALLOWED_MANY, &[("addresses", many.join(", "))]),
            };
            app.notify(NoticeLevel::Info, texts.get(TITLE), body, now)
        }
        Err(error) => app.notify(
            NoticeLevel::Warning,
            texts.get(TITLE),
            texts.fill(keys::VPN_TRUST_FAILED, &[("error", error)]),
            now,
        ),
    }
}

#[cfg(test)]
mod tests;
