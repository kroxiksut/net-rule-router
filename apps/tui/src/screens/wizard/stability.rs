//! The setup's machine-wide answers: routing sites by name (fake-IP) and a
//! window of detailed diagnostic logs, written to the service's stability row
//! as the GUI's first-run window does. Only an administrator may change that
//! row, so a refusal for want of rights is told as the GUI tells it, in the
//! feed, after the setup has handed over.

use nrr_client_logic::stability::{merge_write, patch_changes_nothing, patch_for_platform};
use nrr_ipc_client::{ipc_error_to_wire, ipc_operation_timeout, IpcClient, IpcClientError};
use nrr_shared::ipc::IpcOperationName as Op;
use nrr_shared::platform_profile::PlatformProfile;
use serde_json::{json, Map, Value};

use super::keys as k;
use super::seed_protection;
use crate::backend::{Job, Reply};
use crate::i18n::{Key, Texts};
use crate::screens::binding::error_text;
use crate::state::{AppState, Effect, NoticeLevel};

const ORIGIN: &str = "user:tui";

/// The windows the logs can be written for, in the GUI's order; `None` is off.
const LOG_WINDOWS: [Option<&str>; 4] = [
    None,
    Some("one-hour"),
    Some("four-hours"),
    Some("until-restart"),
];

/// What the write left to tell, once texts are at hand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StabilityNotice {
    /// Fake-IP was asked for and only an administrator can turn it on.
    NeedsAdministrator,
    Failed(String),
}

fn supports() -> Map<String, Value> {
    match serde_json::to_value(PlatformProfile::current().supports) {
        Ok(Value::Object(map)) => map,
        _ => Map::new(),
    }
}

pub fn offers_fake_ip() -> bool {
    let supports = PlatformProfile::current().supports;
    supports.service_stability_config && supports.fake_ip
}

pub fn offers_logs() -> bool {
    PlatformProfile::current().supports.service_stability_config
}

/// Off, then each window, then off again.
pub fn next_log_window(current: Option<&'static str>) -> Option<&'static str> {
    let at = LOG_WINDOWS.iter().position(|w| *w == current).unwrap_or(0);
    LOG_WINDOWS[(at + 1) % LOG_WINDOWS.len()]
}

pub fn log_window_label(window: Option<&str>) -> Key {
    match window {
        Some("one-hour") => k::LOGS_ONE_HOUR,
        Some("four-hours") => k::LOGS_FOUR_HOURS,
        Some("until-restart") => k::LOGS_UNTIL_RESTART,
        _ => k::NO,
    }
}

/// The patch the answers make, cut to what this platform's service applies.
fn patch(fake_ip: bool, logs: Option<&str>) -> Map<String, Value> {
    let mut partial = Map::new();
    partial.insert("fake-ip-enabled".into(), Value::Bool(fake_ip));
    if let Some(window) = logs {
        partial.insert("verbose-logging-change".into(), Value::from(window));
        partial.insert("conn-trace-ndjson-change".into(), Value::from(window));
        partial.insert("conn-trace-gui".into(), Value::Bool(true));
    }
    patch_for_platform(&partial, Some(&supports()))
}

/// Send the answers once per run. A user already set up keeps what the
/// service holds unless they were changed here.
pub fn send(app: &mut AppState) {
    seed_protection(app);
    let state = &app.wizard;
    if state.stability_sent || !app.link.is_connected() {
        return;
    }
    if state.protection_at_start.is_some() && !state.stability_touched {
        return;
    }
    let partial = patch(state.fake_ip, state.diagnostic_logs);
    if partial.is_empty() {
        return;
    }
    app.wizard.stability_sent = true;
    app.outbox.push(job(partial));
}

fn job(partial: Map<String, Value>) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let failed = write(client, &partial)
            .err()
            .map(|error| ipc_error_to_wire(&error).0.to_string());
        let fake_ip = partial.get("fake-ip-enabled") == Some(&Value::Bool(true));
        Reply::new(move |app| {
            let Some(slug) = failed else {
                return;
            };
            let refused = matches!(
                slug.as_str(),
                "forbidden" | "uac-declined" | "elevation-agent-missing" | "elevation-unavailable"
            );
            app.wizard.stability_notice = Some(if refused && fake_ip {
                StabilityNotice::NeedsAdministrator
            } else {
                StabilityNotice::Failed(slug)
            });
        })
    })
}

/// The stability row is replaced whole: the live row with these answers.
fn write(client: &dyn IpcClient, partial: &Map<String, Value>) -> Result<(), IpcClientError> {
    let read = Op::ServiceStabilityConfigGet;
    let live = client.call(read, json!({}), ipc_operation_timeout(read))?;
    let live = live.as_object().cloned().unwrap_or_default();
    // A write that changes nothing would still ask for an administrator.
    if patch_changes_nothing(&live, partial) {
        return Ok(());
    }
    let config = merge_write(&live, &Map::new(), &Map::new(), partial);
    let set = Op::ServiceStabilityConfigSet;
    let payload = json!({ "config": config, "origin": ORIGIN });
    client.call(set, payload, ipc_operation_timeout(set))?;
    Ok(())
}

/// Tell what the last write left, once.
pub fn announce(app: &mut AppState, texts: &Texts, now: std::time::Instant) -> Vec<Effect> {
    let Some(notice) = app.wizard.stability_notice.take() else {
        return Vec::new();
    };
    let (title, body) = match notice {
        StabilityNotice::NeedsAdministrator => (
            texts.get(k::NEEDS_ADMIN_TITLE),
            texts.fill(
                k::NEEDS_ADMIN_BODY,
                &[("setting", texts.get(k::FAKE_IP_SETTING))],
            ),
        ),
        StabilityNotice::Failed(slug) => (
            texts.get(k::STABILITY_FAILED_TITLE),
            format!(
                "{}{}",
                texts.get(k::STABILITY_FAILED),
                error_text(&slug, texts)
            ),
        ),
    };
    app.notify(NoticeLevel::Warning, title, body, now)
}
