//! "Restore my settings" in the terminal: the user's route policy and notice
//! mutes, recorded in their own settings file after every write of theirs the
//! service confirmed, and offered back when a service that was reinstalled or
//! had its data reset answers without them.
//!
//! Nothing is sent unasked: a connect compares, the Status screen says what is
//! missing, and only `r` sends the one write that brings it back. Under `sudo`
//! the rules edited are the administrator's baseline, so there is no settings
//! file of the user's own and nothing is recorded or offered.

use std::path::{Path, PathBuf};

use nrr_client_logic::restore::{
    mutes_to_restore, present_adapter_ids, restore_plan, route_policy_divergence,
};
use nrr_ipc_client::{ipc_error_to_wire, ipc_operation_timeout, IpcClient};
use nrr_shared::ipc::IpcOperationName as Op;
use nrr_shared::ipc_payloads::BlockNoticeMuteDto;
use nrr_shared::user_settings::{
    UserSettings, UserSettingsStore, INTENT_NOTICE_MUTES, INTENT_ROUTE_POLICY,
};
use serde_json::{json, Map, Value};

use crate::backend::{Job, Reply};
use crate::i18n::{key, Key, Texts};
use crate::keys;
use crate::state::{AppState, Effect, NoticeLevel};

pub const OFFER_TITLE: Key = key(
    "notifications.settings-lost.title",
    "The service does not have your settings",
);
pub const OFFER_BODY: Key = key(
    "tui.restore.body",
    "This happens after the service was reinstalled or its data was reset. Missing: {settings}. Press r on the Status screen to restore them.",
);
pub const OFFER_LINE: Key = key(
    "tui.restore.line",
    "The service does not have your settings. r: restore them.",
);
pub const MORE: Key = key("notifications.settings-lost.more", "and {count} more");
pub const MUTES: Key = key("notifications.settings-lost.mutes", "hidden notifications");
pub const OTHER: Key = key(
    "notifications.settings-lost.other-setting",
    "another routing setting",
);
pub const DONE_TITLE: Key = key("notifications.settings-lost.action", "Restore my settings");
pub const RESTORED: Key = key("status.settings-restored", "Your settings were restored.");
pub const NOTHING: Key = key(
    "status.settings-restore-nothing",
    "The service already has your settings.",
);
pub const FAILED: Key = key(
    "tui.restore.failed",
    "Your settings could not be restored: {error}",
);
pub const ADAPTER_MISSING: Key = key(
    "status.settings-restore-adapter-missing",
    "Not restored: the adapter {name} is not on this computer now.",
);
pub const HELP: Key = key(
    "tui.help.status-restore",
    "r: restore your settings to a service that lost them",
);
pub const PLAIN_HELP: Key = key(
    "tui.plain.status-restore",
    "r: restore your settings to a service that lost them",
);

/// Every key this module shows, for the locale test.
#[cfg(test)]
pub const ALL: &[Key] = &[
    OFFER_TITLE,
    OFFER_BODY,
    OFFER_LINE,
    MORE,
    MUTES,
    OTHER,
    DONE_TITLE,
    RESTORED,
    NOTHING,
    FAILED,
    ADAPTER_MISSING,
    HELP,
    PLAIN_HELP,
];

/// What the service lacks while the offer stands.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Offer {
    /// Route-policy keys, sorted.
    pub keys: Vec<String>,
    /// Mutes to bring back.
    pub mutes: usize,
}

/// How a restore went, said once on the feed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Restored { missing: Vec<String> },
    Nothing { missing: Vec<String> },
    Failed(String),
}

#[derive(Debug, Default)]
pub struct RestoreState {
    pub offer: Option<Offer>,
    /// A connect asked for a comparison once its snapshot is in.
    check_pending: bool,
    /// A restore is on its way.
    pub busy: bool,
    /// Said on the feed by the next [`announce`], which has the texts.
    unannounced_offer: bool,
    unannounced_outcome: Option<Outcome>,
}

/// The service came (back): compare once the snapshot is read.
pub fn on_connected(app: &mut AppState) {
    app.restore.check_pending = true;
}

/// A snapshot arrived; compare when a connect asked for it.
pub fn on_snapshot(app: &mut AppState) {
    if !app.restore.check_pending || !app.link.is_connected() {
        return;
    }
    app.restore.check_pending = false;
    let Some(file) = app.rules.settings_file.clone() else {
        return;
    };
    app.outbox.push(check_job(file));
}

fn read_settings(file: &Path) -> Option<UserSettings> {
    UserSettingsStore::at(file.to_path_buf())
        .load()
        .ok()
        .map(Option::unwrap_or_default)
}

fn intent_object(settings: &UserSettings, namespace: &str) -> Map<String, Value> {
    settings
        .intent(namespace)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

fn call(client: &dyn IpcClient, op: Op, payload: Value) -> Result<Value, String> {
    client
        .call(op, payload, ipc_operation_timeout(op))
        .map_err(|e| ipc_error_to_wire(&e).0.to_string())
}

/// The service's row, the adapters present and the mutes it holds.
struct ServiceState {
    policy: Map<String, Value>,
    present: Vec<String>,
    mutes: Value,
}

fn read_service(client: &dyn IpcClient) -> Result<ServiceState, String> {
    let snapshot = call(client, Op::SnapshotInitialGet, json!({}))?;
    let policy = snapshot
        .get("route-policy")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mutes = call(client, Op::BlockNoticeMutesList, json!({}))?;
    Ok(ServiceState {
        policy,
        present: present_adapter_ids(&snapshot),
        mutes: mutes.get("mutes").cloned().unwrap_or(Value::Null),
    })
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn check_job(file: PathBuf) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let offer = read_settings(&file).and_then(|settings| {
            let service = read_service(client).ok()?;
            let policy = intent_object(&settings, INTENT_ROUTE_POLICY);
            let recorded_mutes = settings.intent(INTENT_NOTICE_MUTES).cloned();
            let keys = route_policy_divergence(&policy, &service.policy);
            let mutes = recorded_mutes
                .map(|recorded| mutes_to_restore(&recorded, &service.mutes, now_ms()).len())
                .unwrap_or(0);
            (!keys.is_empty() || mutes > 0).then_some(Offer { keys, mutes })
        });
        Reply::new(move |app| {
            app.restore.unannounced_offer = offer.is_some();
            app.restore.offer = offer;
        })
    })
}

/// `r` on the Status screen: one apply-only write of the route policy, then
/// the mutes. `false` when there is nothing on offer.
pub fn restore(app: &mut AppState) -> bool {
    if app.restore.offer.is_none() || app.restore.busy {
        return false;
    }
    let Some(file) = app.rules.settings_file.clone() else {
        return false;
    };
    app.restore.busy = true;
    app.outbox.push(restore_job(file));
    true
}

fn restore_job(file: PathBuf) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let result = run_restore(client, &file);
        Reply::new(move |app| {
            app.restore.busy = false;
            let outcome = match result {
                Ok(done) => {
                    record_route_policy_in(app.rules.settings_file.as_deref(), &done.request);
                    if let Some(mutes) = &done.mutes {
                        record_mutes_in(app.rules.settings_file.as_deref(), mutes);
                    }
                    app.restore.offer = None;
                    if done.restored {
                        Outcome::Restored {
                            missing: done.missing,
                        }
                    } else {
                        Outcome::Nothing {
                            missing: done.missing,
                        }
                    }
                }
                Err(error) => Outcome::Failed(error),
            };
            app.restore.unannounced_outcome = Some(outcome);
        })
    })
}

struct Done {
    /// The route-policy request sent, empty when none was.
    request: Map<String, Value>,
    /// The mutes the service holds after the last one was brought back.
    mutes: Option<Vec<BlockNoticeMuteDto>>,
    restored: bool,
    missing: Vec<String>,
}

fn run_restore(client: &dyn IpcClient, file: &Path) -> Result<Done, String> {
    let settings = read_settings(file).ok_or_else(|| "user-settings-unavailable".to_owned())?;
    let service = read_service(client)?;
    let present: Vec<&str> = service.present.iter().map(String::as_str).collect();
    let policy = intent_object(&settings, INTENT_ROUTE_POLICY);
    let plan = restore_plan(&policy, &service.policy, &present);
    let missing: Vec<String> = plan.missing.iter().map(|m| m.name.clone()).collect();
    let mut done = Done {
        request: Map::new(),
        mutes: None,
        restored: false,
        missing,
    };
    if let Some(request) = plan.request {
        call(
            client,
            Op::RoutePolicyUpdate,
            Value::Object(request.clone()),
        )?;
        done.request = request;
        done.restored = true;
    }
    let recorded = settings
        .intent(INTENT_NOTICE_MUTES)
        .cloned()
        .unwrap_or(Value::Null);
    for mute in mutes_to_restore(&recorded, &service.mutes, now_ms()) {
        let answer = call(client, Op::BlockNoticeMutesSet, mute)?;
        done.mutes = answer
            .get("mutes")
            .cloned()
            .and_then(|mutes| serde_json::from_value(mutes).ok());
        done.restored = true;
    }
    Ok(done)
}

/// A route-policy write of the user's the service confirmed: the keys it named
/// (`apply-only`), with the values it sent; a key it dropped is dropped.
pub fn record_route_policy(app: &AppState, request: &Map<String, Value>) {
    record_route_policy_in(app.rules.settings_file.as_deref(), request);
}

fn record_route_policy_in(file: Option<&Path>, request: &Map<String, Value>) {
    let Some(file) = file else {
        return;
    };
    let keys = request.get("apply-only").and_then(Value::as_array);
    let merge: Map<String, Value> = keys
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|key| {
            let value = request.get(key).cloned().unwrap_or(Value::Null);
            (key.to_owned(), value)
        })
        .collect();
    if merge.is_empty() {
        return;
    }
    // Best effort: a record that cannot be written costs only a later offer.
    let _ = UserSettingsStore::at(file.to_path_buf())
        .update(|settings| settings.merge_intent(INTENT_ROUTE_POLICY, &merge));
}

/// The user's mutes as the service holds them after a write of theirs.
pub fn record_mutes(app: &AppState, mutes: &[BlockNoticeMuteDto]) {
    record_mutes_in(app.rules.settings_file.as_deref(), mutes);
}

fn record_mutes_in(file: Option<&Path>, mutes: &[BlockNoticeMuteDto]) {
    let (Some(file), Ok(value)) = (file, serde_json::to_value(mutes)) else {
        return;
    };
    let _ = UserSettingsStore::at(file.to_path_buf())
        .update(|settings| settings.set_intent(INTENT_NOTICE_MUTES, value));
}

/// The name a setting is listed under, in the words of the window's settings.
fn setting_name(setting: &str) -> Key {
    match setting {
        "primary" => keys::ROLE_PRIMARY,
        "secondary" => keys::ROLE_SECONDARY,
        "mode" => key(
            "settings.routing.default-route.title",
            "Default route for unmatched traffic",
        ),
        "block-secondary-when-unavailable" => {
            key("settings.routing.kill-switch.title", "Leak protection")
        }
        "kill-switch-enabled" => key(
            "settings.routing.kill-switch.enable-label",
            "Enable leak protection",
        ),
        "kill-switch-protocols" => key(
            "settings.routing.kill-switch.protocols.label",
            "Protocols leak protection cuts",
        ),
        "include-subdomains" => key(
            "settings.routing-behavior.include-subdomains.label",
            "Also cover subdomains for domain rules",
        ),
        "doh-lockdown-enabled" => key(
            "settings.routing.doh-lockdown.label",
            "Block browser DoH/DoT",
        ),
        _ => OTHER,
    }
}

/// The names of what is missing: three, then how many more.
fn names(offer: &Offer, texts: &Texts) -> String {
    let mut names: Vec<String> = Vec::new();
    for setting in &offer.keys {
        let name = texts.get(setting_name(setting));
        if !names.contains(&name) {
            names.push(name);
        }
    }
    if offer.mutes > 0 {
        names.push(texts.get(MUTES));
    }
    let mut shown = names.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
    if names.len() > 3 {
        let more = (names.len() - 3).to_string();
        shown.push(' ');
        shown.push_str(&texts.fill(MORE, &[("count", more)]));
    }
    shown
}

fn with_missing(mut body: String, missing: &[String], texts: &Texts) -> String {
    if !missing.is_empty() {
        body.push(' ');
        body.push_str(&texts.fill(ADAPTER_MISSING, &[("name", missing.join(", "))]));
    }
    body
}

/// Says on the feed what a reply found: an offer, or how a restore went.
pub fn announce(app: &mut AppState, texts: &Texts, now: std::time::Instant) -> Vec<Effect> {
    let mut effects = Vec::new();
    if std::mem::take(&mut app.restore.unannounced_offer) {
        if let Some(offer) = app.restore.offer.clone() {
            let body = texts.fill(OFFER_BODY, &[("settings", names(&offer, texts))]);
            effects.extend(app.notify(NoticeLevel::Warning, texts.get(OFFER_TITLE), body, now));
        }
    }
    if let Some(outcome) = app.restore.unannounced_outcome.take() {
        let (level, body) = match outcome {
            Outcome::Restored { missing } => (
                NoticeLevel::Info,
                with_missing(texts.get(RESTORED), &missing, texts),
            ),
            // Nothing went because its adapter is gone: that is the news.
            Outcome::Nothing { missing } if !missing.is_empty() => {
                let names = missing.join(", ");
                (
                    NoticeLevel::Warning,
                    texts.fill(ADAPTER_MISSING, &[("name", names)]),
                )
            }
            Outcome::Nothing { .. } => (NoticeLevel::Info, texts.get(NOTHING)),
            Outcome::Failed(error) => {
                let error = texts.dynamic(&format!("errors.{error}"), &error);
                (
                    NoticeLevel::Warning,
                    texts.fill(FAILED, &[("error", error)]),
                )
            }
        };
        effects.extend(app.notify(level, texts.get(DONE_TITLE), body, now));
    }
    effects
}

#[cfg(test)]
mod tests;
