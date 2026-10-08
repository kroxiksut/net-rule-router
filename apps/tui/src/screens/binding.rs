//! Adapter roles, shared by the interfaces screen and the setup: which adapters
//! can take a role, how one reads, and the one way a role (or any other
//! route-policy field) reaches the service.

use nrr_client_logic::adapters::{
    display_name, held_other_role, is_own_fake_ip_tun, role_hint, unroutable_reason,
};
use nrr_client_logic::route_policy::{build_full_update_request, name_changes};
use nrr_client_logic::Route;
use nrr_ipc_client::{ipc_error_to_wire, ipc_operation_timeout, IpcClient, IpcClientError};
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    InterfaceRowDto, RouteBindingDto, RoutePolicyDto, SnapshotInterfacesResponse,
};
use serde_json::{json, Map, Value};

use super::interfaces::keys as k;
use super::status::bound_row;
use crate::backend::{Job, Reply};
use crate::i18n::{Key, Texts};
use crate::keys;
use crate::state::AppState;
use crate::view::{Segment, StateTone, ViewLine};

/// The enumerations that are this machine's. Anything else, an unknown
/// spelling included, is placeholder rows that name no adapter here.
const LIVE_SOURCES: [&str; 2] = ["windows-live", "linux-live"];

pub fn rows_are_live(app: &AppState) -> bool {
    app.snapshot
        .as_ref()
        .is_some_and(|s| LIVE_SOURCES.contains(&s.adapters.data_source.as_str()))
}

pub fn binding(app: &AppState, route: Route) -> Option<&RouteBindingDto> {
    let policy = app.snapshot.as_ref()?.route_policy.as_ref()?;
    match route {
        Route::Primary => policy.primary.as_ref(),
        Route::Secondary => policy.secondary.as_ref(),
    }
}

/// The adapters a role can go to, each carrying the role the user's bindings
/// give it — the service leaves `selected_role` empty. The product's own tunnel
/// is never among them; a Bluetooth link only when asked for or bound. Bound
/// adapters come first, main then additional.
pub fn adapters(app: &AppState, with_bluetooth: bool) -> Vec<InterfaceRowDto> {
    let Some(snapshot) = &app.snapshot else {
        return Vec::new();
    };
    let mut rows: Vec<InterfaceRowDto> = snapshot
        .adapters
        .rows
        .iter()
        .filter(|row| !is_own_fake_ip_tun(row))
        .cloned()
        .map(|mut row| {
            row.selected_role = None;
            row
        })
        .collect();
    for route in Route::ALL {
        let Some(bound) = binding(app, route) else {
            continue;
        };
        let index = bound_row(&rows, bound)
            .and_then(|hit| rows.iter().position(|row| std::ptr::eq(row, hit)));
        if let Some(row) = index.and_then(|i| rows.get_mut(i)) {
            if row.selected_role.is_none() {
                row.selected_role = Some(route.as_str().to_string());
            }
        }
    }
    rows.retain(|row| with_bluetooth || !row.is_bluetooth_like || row.selected_role.is_some());
    rows.sort_by_key(|row| match row.selected_role.as_deref() {
        Some("primary") => 0,
        Some("secondary") => 1,
        _ => 2,
    });
    rows
}

pub fn holds(row: &InterfaceRowDto, route: Route) -> bool {
    row.selected_role.as_deref() == Some(route.as_str())
}

/// The key a pending question finds its adapter by again after a refresh.
pub fn row_key(row: &InterfaceRowDto) -> String {
    if row.persistent_id.is_empty() {
        row.name.clone()
    } else {
        row.persistent_id.clone()
    }
}

pub fn find<'a>(rows: &'a [InterfaceRowDto], key: &str) -> Option<&'a InterfaceRowDto> {
    rows.iter().find(|row| row_key(row) == key)
}

pub fn role_label(route: Route) -> Key {
    match route {
        Route::Primary => keys::ROLE_PRIMARY,
        Route::Secondary => keys::ROLE_SECONDARY,
    }
}

/// How an adapter reads in a picker for `route`: what it is, whether it is up,
/// and either the role it already holds or what the recommendation sees in it.
pub fn picker_label(row: &InterfaceRowDto, route: Route, texts: &Texts) -> String {
    let mut parts = vec![display_name(row)];
    if let Some(tech) = row.device_technology.as_deref().filter(|t| !t.is_empty()) {
        parts.push(texts.dynamic(&format!("interfaces.device-technology.{tech}"), tech));
    }
    if !row.kind.is_empty() {
        parts.push(kind_text(row, texts));
    }
    parts.push(if row.availability == "available" {
        texts.dynamic("interfaces.connectivity.available", "Connected")
    } else {
        texts.dynamic("interfaces.connectivity.unavailable", "No connection")
    });
    if let Some(taken) = held_other_role(row, route) {
        parts.push(texts.dynamic(&format!("interfaces.role.taken.{taken}"), taken));
    } else if let Some(hint) = role_hint(row) {
        parts.push(hint_text(hint.as_str(), texts));
    }
    parts.join(" · ")
}

pub fn kind_text(row: &InterfaceRowDto, texts: &Texts) -> String {
    texts.dynamic(&format!("interfaces.kind.{}", row.kind), &row.kind)
}

pub fn hint_text(slug: &str, texts: &Texts) -> String {
    texts.dynamic(&format!("interfaces.hint.{slug}"), slug)
}

/// The availability word; its colour only repeats it.
pub fn availability(row: &InterfaceRowDto, texts: &Texts) -> Segment {
    match row.availability.as_str() {
        "available" => Segment::state(texts.get(keys::AVAILABLE), StateTone::Good),
        "unavailable" => Segment::state(texts.get(keys::UNAVAILABLE), StateTone::Bad),
        _ => Segment::state(texts.get(keys::REQUIRES_CHECK), StateTone::Caution),
    }
}

/// What a role change asks of the service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoleChange {
    Assign {
        route: Route,
        stable_id: String,
        name: String,
    },
    Unassign {
        route: Route,
    },
}

impl RoleChange {
    /// The GUI's binding for `row`: its id, else its name, and the name it
    /// shows, else the id.
    pub fn assign(row: &InterfaceRowDto, route: Route) -> Self {
        let id = row_key(row);
        let name = if row.name.is_empty() {
            id.clone()
        } else {
            row.name.clone()
        };
        Self::Assign {
            route,
            stable_id: id,
            name,
        }
    }

    pub fn route(&self) -> Route {
        match self {
            Self::Assign { route, .. } | Self::Unassign { route } => *route,
        }
    }

    /// Unbinding is always explicit: the slot is left out of the full request.
    fn apply(&self, request: &mut Map<String, Value>) {
        match self {
            Self::Assign {
                route,
                stable_id,
                name,
            } => {
                request.insert(
                    route.as_str().to_string(),
                    json!({ "stable-id": stable_id, "display-name": name, "user-confirmed": true }),
                );
            }
            Self::Unassign { route } => {
                request.remove(route.as_str());
            }
        }
    }

    /// What the change did, in the GUI's words.
    pub fn done_text(&self, texts: &Texts) -> String {
        let role = texts.get(role_label(self.route()));
        match self {
            Self::Assign { name, .. } => texts.fill(
                k::ROLE_SET,
                &[("role", role.as_str()), ("name", name.as_str())],
            ),
            Self::Unassign { .. } => texts.fill(k::ROLE_UNASSIGNED, &[("role", role)]),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// The policy could not be read; nothing was sent.
    Read,
    Write,
}

/// Why a write did not happen: where it stopped and the error's slug.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteFailure {
    pub stage: Stage,
    pub code: String,
}

impl WriteFailure {
    fn new(stage: Stage, error: &IpcClientError) -> Self {
        Self {
            stage,
            code: ipc_error_to_wire(error).0.to_string(),
        }
    }

    /// What happened, then the service's reason; `write_prefix` names what
    /// was being saved.
    pub fn text(&self, write_prefix: Key, texts: &Texts) -> String {
        let reason = error_text(&self.code, texts);
        match self.stage {
            Stage::Read => texts.fill(k::READ_FAILED, &[("error", reason)]),
            Stage::Write => format!("{}{reason}", texts.get(write_prefix)),
        }
    }
}

/// An error slug in words: its `errors.*` text, else the slug itself, so a
/// code this build does not know still says something.
pub fn error_text(code: &str, texts: &Texts) -> String {
    if code.is_empty() {
        return texts.get(k::ERROR_UNKNOWN);
    }
    texts.dynamic(&format!("errors.{code}"), code)
}

/// A route-policy write. `route.policy.update` replaces the whole row, so the
/// request is rebuilt from the policy as stored right now and only `edit`'s
/// keys change: a field left out would fall back to the service default and
/// quietly undo a setting. Jobs run one at a time, so a second write reads
/// after the first one landed.
pub fn policy_write(
    edit: impl FnOnce(&mut Map<String, Value>) + Send + 'static,
    done: impl FnOnce(&mut AppState, Result<(), WriteFailure>) + Send + 'static,
) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let result = write_policy(client, edit);
        Reply::new(move |app| {
            let result = result.map(|stored| {
                if let (Some(stored), Some(snapshot)) = (stored, app.snapshot.as_mut()) {
                    snapshot.route_policy = Some(stored);
                }
            });
            done(app, result);
        })
    })
}

/// The answer is the policy now stored; an answer this build cannot read
/// leaves the old one shown until the next snapshot.
fn write_policy(
    client: &dyn IpcClient,
    edit: impl FnOnce(&mut Map<String, Value>),
) -> Result<Option<RoutePolicyDto>, WriteFailure> {
    let read = IpcOperationName::SnapshotInitialGet;
    let snapshot = client
        .call(read, Value::Object(Map::new()), ipc_operation_timeout(read))
        .map_err(|e| WriteFailure::new(Stage::Read, &e))?;
    let stored = snapshot
        .get("route-policy")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    // No local mode preference here: an empty fallback reads as the contract
    // default.
    let base = build_full_update_request(&stored, "");
    let mut request = base.clone();
    edit(&mut request);
    // Only what changed: a whole row would revert what the tray wrote since.
    let Some(request) = name_changes(&base, request) else {
        return Ok(serde_json::from_value(Value::Object(stored)).ok());
    };
    let write = IpcOperationName::RoutePolicyUpdate;
    let answer = client
        .call(write, Value::Object(request), ipc_operation_timeout(write))
        .map_err(|e| WriteFailure::new(Stage::Write, &e))?;
    Ok(serde_json::from_value(answer).ok())
}

/// A role change as a policy write.
pub fn role_write(
    change: RoleChange,
    done: impl FnOnce(&mut AppState, &RoleChange, Result<(), WriteFailure>) + Send + 'static,
) -> Job {
    let edit = change.clone();
    policy_write(
        move |request| edit.apply(request),
        move |app, result| done(app, &change, result),
    )
}

/// Re-read the adapters, as the GUI does when its interfaces section comes
/// into view. `probe` also asks each adapter's external address — that leaves
/// the machine, so only on the user's word.
pub fn adapters_read(
    probe: bool,
    done: impl FnOnce(&mut AppState, Result<(), String>) + Send + 'static,
) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let op = if probe {
            IpcOperationName::InterfacesRefreshRequest
        } else {
            IpcOperationName::SnapshotInterfacesGet
        };
        let result = client
            .call(op, json!({}), ipc_operation_timeout(op))
            .map_err(|e| ipc_error_to_wire(&e).0.to_string())
            .and_then(|answer| {
                serde_json::from_value::<SnapshotInterfacesResponse>(answer)
                    .map_err(|_| "bad-response".to_string())
            });
        Reply::new(move |app| {
            let result = result.map(|fresh| {
                // An answer without rows (an older service) keeps the list shown.
                if let (false, Some(snapshot)) = (fresh.rows.is_empty(), app.snapshot.as_mut()) {
                    snapshot.adapters = fresh;
                }
            });
            done(app, result);
        })
    })
}

/// Whether leak protection is armed, for the warning about an adapter with no
/// way out.
pub fn kill_switch_on(app: &AppState) -> bool {
    app.snapshot
        .as_ref()
        .and_then(|s| s.route_policy.as_ref())
        .is_some_and(|p| p.kill_switch_enabled)
}

/// The GUI's warning before an adapter with no way out takes a role.
pub fn unroutable_lines(
    row: &InterfaceRowDto,
    route: Route,
    kill_switch: bool,
    texts: &Texts,
) -> Vec<ViewLine> {
    let mut lines = vec![ViewLine::text(
        texts.fill(k::UNROUTABLE_ADAPTER, &[("name", display_name(row))]),
    )];
    let (body, effect) = match route {
        Route::Primary => (k::UNROUTABLE_BODY_PRIMARY, k::UNROUTABLE_EFFECT_PRIMARY),
        Route::Secondary => (k::UNROUTABLE_BODY, k::UNROUTABLE_EFFECT),
    };
    lines.push(ViewLine::text(texts.get(body)));
    if let Some(reason) = unroutable_reason(row) {
        let slug = reason.as_str();
        lines.push(ViewLine::text(texts.dynamic(
            &format!("dialog.unroutable-secondary.reason-{slug}"),
            slug,
        )));
    }
    lines.push(ViewLine::text(texts.get(effect)));
    if route == Route::Secondary {
        lines.push(ViewLine::text(texts.get(if kill_switch {
            k::UNROUTABLE_KILL_SWITCH_ON
        } else {
            k::UNROUTABLE_KILL_SWITCH_OFF
        })));
    }
    lines
}

/// `%1`, `%2`, … filled in order, for the GUI keys written that way.
pub fn positional(template: &str, values: &[&str]) -> String {
    values
        .iter()
        .enumerate()
        .rev()
        .fold(template.to_string(), |text, (i, value)| {
            text.replace(&format!("%{}", i + 1), value)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positional_fills_in_order() {
        assert_eq!(positional("a %1 b %2", &["x", "y"]), "a x b y");
    }

    #[test]
    fn unbinding_leaves_the_slot_out() {
        let mut request = Map::new();
        request.insert("primary".into(), json!({ "stable-id": "A" }));
        RoleChange::Unassign {
            route: Route::Primary,
        }
        .apply(&mut request);
        assert!(!request.contains_key("primary"));
    }
}
