//! The programs that keep working over the main link while leak protection is
//! on (a VPN client, say): listed, added by path and removed, through the one
//! operation the window writes them with. The write replaces the whole set,
//! so each change starts from a fresh read and is worked out by
//! `nrr-client-logic`. A scan lists the VPN programs found on this computer,
//! each ticked when it is confirmed, as the window's picker does. Below them,
//! the other VPNs' servers the user let through, each taken back the same way.

use nrr_client_logic::vpn_client_trust::{
    confirmed_apps, picker_preselected, picker_result, picker_tickable, removed_apps,
    LinkProviderApp, PickerRow, TrustOffer, PICKER_KERNEL_TUNNEL_SOURCE,
};
use nrr_client_logic::vpn_gateway::program_file_name;
use nrr_client_logic::vpn_gateway_trust::removed_gateways;
use nrr_ipc_client::IpcClient;
use nrr_platform_api::{VpnCandidate, VpnCandidateSource};
use nrr_shared::display_text::display_text;
use nrr_shared::ipc::IpcOperationName as Op;
use nrr_shared::ipc_payloads::{LinkProviderAppDto, RouteLinkProviderSetRequest, VpnGatewayDto};
use serde_json::{Map, Value};

use super::items::Words;
use super::{jobs, text, Failure, Input, Loadable};
use crate::backend::{Job, Reply};
use crate::i18n::{key, Key};
use crate::state::AppState;

pub const TITLE: Key = key("vpn-onboarding.title", "Your VPN client");
pub const NOTE: Key = key(
    "settings.routing.providers.note",
    "Programs that keep working over your main link while leak protection is on, such as your VPN client. Type a program's full path to add one.",
);
pub const EMPTY: Key = key(
    "settings.routing.providers.empty",
    "No programs are confirmed yet.",
);
pub const REMOVE: Key = key(
    "settings.routing.providers.remove",
    "Remove {name} ({path})",
);
pub const NEW: Key = key(
    "settings.routing.providers.new",
    "Program to add (full path)",
);
pub const NEED_PATH: Key = key(
    "settings.routing.providers.need-path",
    "Type the program's full path first.",
);
pub const ADDED: Key = key(
    "vpn-onboarding.confirmed-status",
    "NetRuleRouter will keep {name} working over your main link while leak protection is on.",
);
pub const REMOVED: Key = key(
    "settings.routing.providers.removed",
    "{name} was removed. Leak protection no longer keeps it working over your main link.",
);

pub const GATEWAYS_TITLE: Key = key("settings.vpn-gateways.title", "Other VPNs you allowed");
pub const GATEWAYS_NOTE: Key = key(
    "settings.vpn-gateways.note",
    "Their servers can be reached over the main connection while leak protection is on, for the VPN's own connection only.",
);
pub const GATEWAY_SYSTEM: Key = key("settings.vpn-gateways.system", "built into the system");
pub const GATEWAY_REMOVE: Key = key(
    "settings.vpn-gateways.remove",
    "Remove the allowed VPN server {address}",
);
pub const GATEWAY_REMOVED: Key = key(
    "settings.vpn-gateways.removed-status",
    "The VPN server {address} is no longer let through.",
);

pub const SCAN: Key = key("vpn-onboarding.scan", "Scan for VPN apps");
pub const SCAN_AGAIN: Key = key("vpn-onboarding.scan-again", "Scan again");
pub const SCANNING: Key = key("vpn-onboarding.scanning", "Scanning…");
pub const FOUND_HINT: Key = key(
    "vpn-onboarding.multi-hint",
    "Tick every program that's part of your VPN — for example a client together with its background service or command-line helper. All of them will keep working over your main link.",
);
pub const FOUND_NONE: Key = key(
    "vpn-onboarding.empty",
    "No VPN apps found. If you use one, pick it manually below.",
);
pub const FOUND_NO_FILE: Key = key("vpn-onboarding.not-found", "not found — pick manually");
pub const RUNNING: Key = key("vpn-onboarding.running", "running now");
pub const TUNNEL_ASSIGN: Key = key(
    "vpn-onboarding.kernel-tunnel-assign",
    "Kernel tunnel {name} — assign adapter {interface} as the additional link",
);
pub const TUNNEL_DOWN: Key = key(
    "vpn-onboarding.kernel-tunnel-down",
    "Tunnel {name} is not up",
);
pub const CLEARED: Key = key(
    "vpn-onboarding.cleared-status",
    "No program is kept working over your main link any more.",
);

#[cfg(test)]
pub fn keys() -> Vec<Key> {
    vec![
        SCAN,
        SCAN_AGAIN,
        SCANNING,
        FOUND_HINT,
        FOUND_NONE,
        FOUND_NO_FILE,
        RUNNING,
        TUNNEL_ASSIGN,
        TUNNEL_DOWN,
        CLEARED,
        TITLE,
        NOTE,
        EMPTY,
        REMOVE,
        NEW,
        NEED_PATH,
        ADDED,
        REMOVED,
        GATEWAYS_TITLE,
        GATEWAYS_NOTE,
        GATEWAY_SYSTEM,
        GATEWAY_REMOVE,
        GATEWAY_REMOVED,
    ]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderRow {
    Remove(usize),
    New,
    Add,
    /// Look for VPN programs on this computer.
    Scan,
    /// A program the scan found, by its place in the list on screen.
    Found(usize),
    /// A confirmed VPN gateway, by its place in the list on screen.
    RemoveGateway(usize),
}

#[derive(Debug, Default)]
pub struct ProvidersState {
    /// The path typed and not yet added.
    pub new: String,
    /// What the last scan found; `None` until one ran.
    pub found: Option<Vec<PickerRow>>,
    pub scanning: bool,
}

fn source_slug(source: VpnCandidateSource) -> &'static str {
    match source {
        VpnCandidateSource::RunningProcess => "running-process",
        VpnCandidateSource::InstalledProgram => "installed-program",
        VpnCandidateSource::KernelTunnel => PICKER_KERNEL_TUNNEL_SOURCE,
    }
}

/// The scan's candidates as the picker's rows.
pub fn found_rows(candidates: &[VpnCandidate]) -> Vec<PickerRow> {
    candidates
        .iter()
        .map(|c| PickerRow {
            display_name: c.display_name.clone(),
            exe_path: c.exe_path.clone().unwrap_or_default(),
            running: c.running,
            source: source_slug(c.source).to_owned(),
            interface_name: c.interface.clone().unwrap_or_default(),
        })
        .collect()
}

/// Whether `row` is among the confirmed programs of `policy`.
pub fn is_confirmed(policy: &Map<String, Value>, row: &PickerRow) -> bool {
    picker_tickable(row)
        && !picker_preselected(std::slice::from_ref(row), &apps_of(policy)).is_empty()
}

/// What a found row says: its name, path and whether it runs; a tunnel names
/// its link, a program without its file says so.
pub fn found_label(row: &PickerRow) -> Words {
    let name = display_text(&row.display_name).into_owned();
    if row.source == PICKER_KERNEL_TUNNEL_SOURCE {
        return if row.running && !row.interface_name.is_empty() {
            Words::Fill(
                TUNNEL_ASSIGN,
                vec![
                    ("name", name),
                    ("interface", display_text(&row.interface_name).into_owned()),
                ],
            )
        } else {
            Words::Fill(TUNNEL_DOWN, vec![("name", name)])
        };
    }
    let mut words = vec![Words::Raw(name), Words::Raw(" (".to_owned())];
    words.push(if picker_tickable(row) {
        Words::Raw(display_text(&row.exe_path).into_owned())
    } else {
        Words::Key(FOUND_NO_FILE)
    });
    words.push(Words::Raw(")".to_owned()));
    if row.running {
        words.push(Words::Raw(", ".to_owned()));
        words.push(Words::Key(RUNNING));
    }
    Words::Join(words)
}

/// Look again; the rows on screen stay until the answer replaces them.
pub fn scan(app: &mut AppState) {
    if app.settings.providers.scanning {
        return;
    }
    app.settings.providers.scanning = true;
    app.outbox.push(Box::new(|_client: &dyn IpcClient| {
        let found = found_rows(&crate::platform::vpn_discovery().discover_vpn_candidates());
        Reply::new(move |app| {
            app.settings.providers.scanning = false;
            app.settings.providers.found = Some(found);
        })
    }));
}

const POLICY_KEY: &str = "secondary-link-provider-apps";

/// The confirmed programs of a `route-policy` read, in the service's order.
pub fn apps_of(policy: &Map<String, Value>) -> Vec<LinkProviderApp> {
    let text_of = |app: &Value, field: &str| {
        app.get(field)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    policy
        .get(POLICY_KEY)
        .and_then(Value::as_array)
        .map(|apps| {
            apps.iter()
                .map(|app| LinkProviderApp {
                    exe_path: text_of(app, "exe-path"),
                    display_name: text_of(app, "display-name"),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// What the row for `app` is called: its name, else its file name.
pub fn name_of(app: &LinkProviderApp) -> String {
    let name = if app.display_name.trim().is_empty() {
        program_file_name(&app.exe_path)
    } else {
        app.display_name.trim()
    };
    display_text(name).into_owned()
}

/// Which program a confirmed gateway belongs to, as its row names it.
pub fn gateway_program(gateway: &VpnGatewayDto) -> Words {
    match program_file_name(&gateway.program) {
        "" => Words::Key(GATEWAY_SYSTEM),
        name => Words::Raw(display_text(name).into_owned()),
    }
}

enum Change {
    Add(String),
    Remove(String),
    /// Tick (`true`) or untick one found program; the other found rows keep
    /// what the service holds for them.
    Tick {
        rows: Vec<PickerRow>,
        path: String,
        on: bool,
    },
}

pub fn activate(app: &mut AppState, row: ProviderRow, input: Input) -> Option<Job> {
    match (row, input) {
        (ProviderRow::New, Input::Text(path)) => {
            app.settings.providers.new = path;
            None
        }
        (ProviderRow::Add, Input::Run) => {
            let typed = app.settings.providers.new.trim().to_owned();
            if typed.is_empty() {
                app.settings.refuse(Words::Key(NEED_PATH));
                return None;
            }
            Some(write(Change::Add(typed)))
        }
        (ProviderRow::Remove(index), Input::Run) => {
            let path = app
                .settings
                .data
                .policy
                .ready()
                .and_then(|policy| apps_of(policy).into_iter().nth(index))
                .map(|a| a.exe_path)?;
            Some(write(Change::Remove(path)))
        }
        (ProviderRow::Scan, Input::Run) => {
            scan(app);
            None
        }
        (ProviderRow::Found(index), Input::Toggle) => {
            let rows = app.settings.providers.found.clone()?;
            let row = rows.get(index).filter(|r| picker_tickable(r))?.clone();
            let on = !app
                .settings
                .data
                .policy
                .ready()
                .is_some_and(|policy| is_confirmed(policy, &row));
            Some(write(Change::Tick {
                rows,
                path: row.exe_path,
                on,
            }))
        }
        (ProviderRow::RemoveGateway(index), Input::Run) => {
            let address = app.vpn_gateway_trust.confirmed.get(index)?.address.clone();
            Some(revoke_gateway(address))
        }
        _ => None,
    }
}

/// The new set for `change` over what the service holds now.
fn changed(existing: &[LinkProviderApp], change: &Change) -> Vec<LinkProviderApp> {
    match change {
        Change::Add(path) => confirmed_apps(
            existing,
            &TrustOffer {
                exe_path: path.clone(),
                name: String::new(),
                bundled_exe_paths: Vec::new(),
            },
            false,
        ),
        Change::Remove(path) => removed_apps(existing, path),
        Change::Tick { rows, path, on } => {
            let mut selected: Vec<String> = picker_preselected(rows, existing)
                .into_iter()
                .filter(|p| !p.eq_ignore_ascii_case(path))
                .collect();
            if *on {
                selected.push(path.clone());
            }
            picker_result(rows, &selected, existing)
        }
    }
}

fn write(change: Change) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let result = replace(client, &change);
        Reply::new(move |app| match result {
            Ok((policy, words)) => {
                if matches!(change, Change::Add(_)) {
                    app.settings.providers.new.clear();
                }
                app.settings.data.policy = Loadable::Ready(policy);
                app.settings.done(words);
            }
            Err(failure) => app.settings.failed(text::NOT_SAVED, failure),
        })
    })
}

fn revoke_gateway(address: String) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let result = crate::vpn_gateway_trust::rewrite(client, |existing| {
            removed_gateways(existing, &address)
        });
        Reply::new(move |app| match result {
            Ok(stored) => {
                app.vpn_gateway_trust.confirmed = stored;
                app.settings.done(Words::Fill(
                    GATEWAY_REMOVED,
                    vec![("address", display_text(&address).into_owned())],
                ));
            }
            Err(error) => app
                .settings
                .failed(text::NOT_SAVED, Failure::from_ipc(&error)),
        })
    })
}

fn replace(
    client: &dyn IpcClient,
    change: &Change,
) -> Result<(Map<String, Value>, Words), Failure> {
    let existing = apps_of(&jobs::policy_of(client)?);
    let apps = changed(&existing, change);
    let request = RouteLinkProviderSetRequest {
        role: "secondary".to_owned(),
        link_provider_apps: apps
            .iter()
            .map(|a| LinkProviderAppDto {
                exe_path: a.exe_path.clone(),
                display_name: a.display_name.clone(),
            })
            .collect(),
    };
    jobs::call(
        client,
        Op::RouteLinkProviderSet,
        serde_json::to_value(&request).unwrap_or(Value::Null),
    )?;
    let words = match change {
        Change::Add(path) => Words::Fill(
            ADDED,
            vec![("name", display_text(program_file_name(path)).into_owned())],
        ),
        Change::Tick { .. } if apps.is_empty() => Words::Key(CLEARED),
        Change::Tick { path, on: true, .. } => Words::Fill(
            ADDED,
            vec![("name", display_text(program_file_name(path)).into_owned())],
        ),
        Change::Tick { path, .. } | Change::Remove(path) => {
            let gone = existing
                .iter()
                .find(|a| a.exe_path.eq_ignore_ascii_case(path.trim()))
                .map_or_else(
                    || display_text(program_file_name(path)).into_owned(),
                    name_of,
                );
            Words::Fill(REMOVED, vec![("name", gone)])
        }
    };
    Ok((jobs::policy_of(client)?, words))
}

#[cfg(test)]
mod tests;
