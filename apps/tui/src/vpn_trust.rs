//! "Is this your VPN?" — the terminal UI's answer to a program named like a
//! VPN client that leak protection does not trust by place.
//!
//! The Status screen lists the service's pending clients and asks about the
//! first: `t` confirms it alone, `T` with the programs of its protected install
//! tree. The write replaces the link provider set with what the service holds
//! now plus the answer — the same decision the window makes, from
//! `nrr-client-logic`.

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
use serde_json::{json, Value};

use crate::backend::{Job, Reply};
use crate::i18n::{key, Key, Texts};
use crate::keys;
use crate::screens::suggestions::call;
use crate::state::{AppState, Effect, NoticeLevel};

pub const HELP: Key = key(
    "tui.help.status-vpn-trust",
    "t: confirm the first listed program as your VPN (T: with the programs it ships with), so leak protection keeps it working",
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

/// Confirm the first pending program, alone or with the programs it ships
/// with, as the window asks each one. `false` when there is nothing to confirm
/// (or no bundle to take along), the service is away or a write is in flight.
pub fn trust_first(app: &mut AppState, with_bundle: bool) -> bool {
    if app.vpn_trust.busy || !app.link.is_connected() {
        return false;
    }
    let Some(offer) = offers(&app.vpn_trust.pending).into_iter().next() else {
        return false;
    };
    if with_bundle && offer.bundled_exe_paths.is_empty() {
        return false;
    }
    app.vpn_trust.busy = true;
    app.outbox.push(trust_job(offer, with_bundle));
    true
}

/// The first question as the Status screen asks it: the program's name and
/// how many programs it ships with.
pub fn first_question(pending: &[PendingVpnClientDto]) -> Option<(String, usize)> {
    offers(pending).into_iter().next().map(|o| {
        (
            display_text(&o.name).into_owned(),
            o.bundled_exe_paths.len(),
        )
    })
}

fn trust_job(offer: TrustOffer, with_bundle: bool) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let result = confirm(client, &offer, with_bundle);
        Reply::new(move |app| {
            app.vpn_trust.busy = false;
            if result.is_ok() {
                // The service republishes its list on the next compute; until
                // then this question is answered and the next one is up.
                let answered = |path: &str| path.trim().eq_ignore_ascii_case(&offer.exe_path);
                app.vpn_trust.pending.retain(|c| !answered(&c.exe_path));
            }
            app.vpn_trust.unannounced = Some(result);
        })
    })
}

/// What the service holds now plus the answer, written back. The write
/// replaces the whole set, so it starts from a fresh read: an answer given in
/// the window since the last snapshot is kept.
fn confirm(client: &dyn IpcClient, offer: &TrustOffer, with_bundle: bool) -> Result<usize, String> {
    let snapshot: Value = call(client, IpcOperationName::SnapshotInitialGet, &json!({}))
        .map_err(|error| error.message)?;
    let stored: Vec<LinkProviderAppDto> = match snapshot
        .get("route-policy")
        .and_then(|policy| policy.get("secondary-link-provider-apps"))
    {
        Some(list) => serde_json::from_value(list.clone()).map_err(|e| e.to_string())?,
        None => Vec::new(),
    };
    let existing: Vec<LinkProviderApp> = stored
        .into_iter()
        .map(|a| LinkProviderApp {
            exe_path: a.exe_path,
            display_name: a.display_name,
        })
        .collect();
    let request = RouteLinkProviderSetRequest {
        role: "secondary".to_string(),
        link_provider_apps: confirmed_apps(&existing, offer, with_bundle)
            .into_iter()
            .map(|a| LinkProviderAppDto {
                exe_path: a.exe_path,
                display_name: a.display_name,
            })
            .collect(),
    };
    let _: RouteLinkProviderSetResponse =
        call(client, IpcOperationName::RouteLinkProviderSet, &request)
            .map_err(|error| error.message)?;
    Ok(1 + if with_bundle {
        offer.bundled_exe_paths.len()
    } else {
        0
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

#[cfg(test)]
mod tests {
    use nrr_ipc_client::ConnectionStatus;
    use serde_json::{json, Value};

    use super::*;
    use crate::link::Link;
    use crate::testing::{app_at, FakeService, Fixture};

    const OLD: &str = r"C:\Tools\old-vpn.exe";
    const B: &str = r"C:\Users\someone\b-vpn.exe";
    const C: &str = r"C:\Users\someone\c-vpn.exe";
    const B_HELPER: &str = r"C:\Program Files\B\b-helper.exe";

    fn pending(path: &str, bundled: &[&str]) -> PendingVpnClientDto {
        PendingVpnClientDto {
            exe_path: path.to_owned(),
            bundled_exe_paths: bundled.iter().map(|p| (*p).to_owned()).collect(),
        }
    }

    /// The service holds `stored`; whatever it is sent comes back as stored.
    fn service(stored: &[&str]) -> FakeService {
        let fake = FakeService::new(ConnectionStatus::Connected);
        let apps: Vec<Value> = stored
            .iter()
            .map(|p| json!({ "exe-path": p, "display-name": "" }))
            .collect();
        fake.answer(
            IpcOperationName::SnapshotInitialGet,
            json!({ "route-policy": { "secondary-link-provider-apps": apps } }),
        );
        fake.answer(
            IpcOperationName::RouteLinkProviderSet,
            json!({ "role": "secondary", "link-provider-apps": [] }),
        );
        fake
    }

    fn run(app: &mut AppState, fake: &FakeService) {
        for job in app.outbox.take() {
            (job(fake).0)(app);
        }
    }

    fn written(fake: &FakeService) -> Vec<String> {
        let sent = fake.sent(IpcOperationName::RouteLinkProviderSet);
        assert_eq!(sent.len(), 1, "{sent:?}");
        sent[0]["link-provider-apps"]
            .as_array()
            .map(|apps| {
                apps.iter()
                    .filter_map(|a| a["exe-path"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// A program confirmed in the window after the last snapshot is in the
    /// service's list, not in the TUI's; the write keeps it.
    #[test]
    fn the_write_starts_from_what_the_service_holds_now() {
        let fake = service(&[OLD]);
        let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
        app.vpn_trust.pending = vec![pending(B, &[])];
        assert!(trust_first(&mut app, false));
        run(&mut app, &fake);
        assert_eq!(written(&fake), vec![OLD.to_owned(), B.to_owned()]);
        assert!(!app.vpn_trust.busy);
        assert!(app.vpn_trust.pending.is_empty());
    }

    /// One key answers one program; the bundle goes along only when asked.
    #[test]
    fn one_program_at_a_time_and_its_bundle_only_on_request() {
        let fake = service(&[]);
        let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
        app.vpn_trust.pending = vec![pending(B, &[B_HELPER]), pending(C, &[])];
        assert!(trust_first(&mut app, false));
        run(&mut app, &fake);
        assert_eq!(written(&fake), vec![B.to_owned()]);
        assert_eq!(app.vpn_trust.pending, vec![pending(C, &[])]);

        assert!(
            !trust_first(&mut app, true),
            "no bundle to take along with this one"
        );
        let fake = service(&[]);
        app.vpn_trust.pending = vec![pending(B, &[B_HELPER])];
        assert!(trust_first(&mut app, true));
        run(&mut app, &fake);
        assert_eq!(written(&fake), vec![B.to_owned(), B_HELPER.to_owned()]);
    }
}
