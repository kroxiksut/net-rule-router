//! The full reset: the window's steps, in the order `nrr-client-logic` gives
//! them, over the same operations. Whatever needs the window's own files (the
//! saved comments) is not this terminal's to clear and is skipped; whatever
//! needs administrator rights is refused with how to start the terminal with
//! them, and then the reset stops before it touches the service.

use std::time::{Duration, Instant};

use base64::Engine as _;
use nrr_client_logic::full_reset::{next, Next, Outcome, Step};
use nrr_ipc_client::{ipc_operation_timeout, IpcClient};
use nrr_platform_api::service_control::{ServiceControlError, ServiceControlPort, ServiceRunState};
use nrr_shared::ipc::IpcOperationName as Op;
use nrr_shared::ipc_payloads::{
    LogsClearRequest, PresetImportPayload, PrincipalDataCountResponse, PrincipalDataPurgeRequest,
};
use nrr_shared::user_settings::UserSettingsStore;
use serde_json::Value;

use super::items::Words;
use super::{Failure, Input, Loadable};
use crate::backend::{Job, RegistrationProbe, Reply};
use crate::i18n::{key, Key};
use crate::screens::wizard::import;
use crate::state::AppState;

pub const TITLE: Key = key("dialog.full-reset.title", "Full reset");
pub const BODY: Key = key(
    "dialog.full-reset.body",
    "This resets ALL application settings to defaults, deletes the rules the service keeps for you (back to a post-install state), wipes saved comments and logs, and stops the background service. Your own rules files on disk are left untouched, and the background service is NOT uninstalled. This cannot be undone.",
);
pub const OTHERS: Key = key(
    "dialog.full-reset.other-users",
    "Other users of this computer have rules here too ({count}). What should be cleared?",
);
pub const SCOPE: Key = key("tui.settings.reset.scope", "Whose data to clear");
pub const MINE: Key = key("dialog.full-reset.scope-mine", "Only my data");
pub const EVERYONE: Key = key(
    "tui.settings.reset.scope-everyone",
    "Every user on this computer (needs nrr-tui started as administrator)",
);
pub const RUN: Key = key("dialog.full-reset.confirm", "Reset everything");
pub const RUNNING: Key = key("status.full-reset-running", "Performing full reset…");
pub const DONE: Key = key(
    "tui.settings.reset.done",
    "Full reset is done and the service is stopped. Close this terminal and any NetRuleRouter window, then start again.",
);
pub const PARTIAL: Key = key(
    "dialog.full-reset-done.service-warn",
    "Note: some service-side data could not be cleared (administrator approval may be required, or a temporary error occurred). Re-run the reset.",
);
pub const STOPPED: Key = key(
    "tui.settings.reset.needs-elevation",
    "Full reset stopped before the rules were cleared and the service was stopped: {error}",
);

#[cfg(test)]
pub fn keys() -> Vec<Key> {
    vec![
        TITLE, BODY, OTHERS, SCOPE, MINE, EVERYONE, RUN, RUNNING, DONE, PARTIAL, STOPPED,
    ]
}

/// A service stop that has not finished in this time is reported as failed.
const STOP_WAIT: Duration = Duration::from_secs(30);
/// How long a service started for the reset gets to come up and answer.
const START_WAIT: Duration = Duration::from_secs(30);
const ANSWER_WAIT: Duration = Duration::from_secs(15);
const ANSWER_POLL: Duration = Duration::from_millis(500);

/// The rules file with no rule in it, the state a fresh install starts from.
const EMPTY_RULES: &str =
    "--- Zones\n\n--- Domains\n\n--- IP\n\n--- Windows\n\n--- Linux\n\n--- MacOS\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResetRow {
    Scope,
    Run,
}

#[derive(Debug, Default)]
pub struct ResetState {
    /// How many other users the service holds rules for.
    pub others: Loadable<u32>,
    /// Clear every user's data, not just the caller's.
    pub everyone: bool,
}

pub fn load_others() -> Job {
    Box::new(|client: &dyn IpcClient| {
        let result = call(
            client,
            Op::PrincipalDataCount,
            Value::Object(Default::default()),
        )
        .and_then(|v| {
            serde_json::from_value::<PrincipalDataCountResponse>(v).map_err(|e| Failure {
                slug: "bad-response".to_owned(),
                elevation: false,
                detail: e.to_string(),
            })
        })
        .map(|answer| answer.other_principals);
        Reply::new(move |app| {
            app.settings.reset.others = match result {
                Ok(n) => Loadable::Ready(n),
                Err(failure) => Loadable::Failed(failure),
            }
        })
    })
}

/// A row's input. Returns the job to queue, if any; the running notice is
/// this module's own.
pub fn activate(app: &mut AppState, row: ResetRow, input: Input) -> Option<Job> {
    match (row, input) {
        (ResetRow::Scope, Input::Pick(slug)) => {
            app.settings.reset.everyone = slug == "everyone";
            None
        }
        (ResetRow::Run, Input::Run) => {
            let everyone = app.settings.reset.everyone
                && matches!(app.settings.reset.others, Loadable::Ready(n) if n > 0);
            app.settings.say(Words::Key(RUNNING), None);
            app.outbox.push(full_reset(
                everyone,
                app.settings.service_probe,
                app.rules.settings_file.clone(),
            ));
            None
        }
        _ => None,
    }
}

fn call(client: &dyn IpcClient, op: Op, payload: Value) -> Result<Value, Failure> {
    client
        .call(op, payload, ipc_operation_timeout(op))
        .map_err(|e| Failure::from_ipc(&e))
}

fn outcome<T>(result: Result<T, Failure>) -> Outcome {
    match result {
        Ok(_) => Outcome::Ok,
        Err(f) if f.elevation => Outcome::Forbidden,
        Err(_) => Outcome::Failed,
    }
}

fn to_value<T: serde::Serialize>(request: &T) -> Value {
    serde_json::to_value(request).unwrap_or(Value::Null)
}

fn empty_rules_payload() -> Value {
    let bytes = base64::engine::general_purpose::STANDARD.encode(EMPTY_RULES);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    to_value(&PresetImportPayload {
        primary_bytes_b64: Some(bytes.clone()),
        secondary_bytes_b64: Some(bytes),
        include_child_processes: false,
        correlation_id: Some(format!("tui-full-reset-{}-{nanos}", std::process::id())),
        ..PresetImportPayload::default()
    })
}

fn run_step(
    client: &dyn IpcClient,
    step: Step,
    everyone: bool,
    stop: &dyn Fn() -> Outcome,
) -> Outcome {
    match step {
        Step::ClearLogs => outcome(call(
            client,
            Op::LogsClear,
            to_value(&LogsClearRequest {
                include_archives: true,
                dry_run: false,
            }),
        )),
        // The saved comments belong to the window; this terminal keeps none.
        Step::ResetSidecar => Outcome::Skipped,
        Step::PurgePrincipalData => outcome(call(
            client,
            Op::PrincipalDataPurge,
            to_value(&PrincipalDataPurgeRequest {
                include_rules_history: true,
                all_principals: everyone,
            }),
        )),
        Step::ApplyEmptyRules => match import::run(client, &empty_rules_payload()) {
            Ok(()) => Outcome::Ok,
            Err(slug) if slug == "forbidden" => Outcome::Forbidden,
            Err(_) => Outcome::Failed,
        },
        Step::StopService => stop(),
    }
}

/// A stopped service answers none of the steps, so the reset would only say
/// what it could not clear: it is started first, and the last step stops it
/// again. A start that fails or is refused leaves the steps to report that.
pub(super) fn start_if_stopped(
    port: Option<&dyn ServiceControlPort>,
    client: &dyn IpcClient,
    answer_wait: Duration,
) -> bool {
    let Some(port) = port else { return false };
    let stopped = matches!(
        port.query(),
        Ok(Some(report)) if report.run_state == ServiceRunState::Stopped
    );
    if !stopped || port.start(START_WAIT).is_err() {
        return false;
    }
    // Running to the service manager is not yet listening on its channel.
    client.force_reconnect();
    let deadline = Instant::now() + answer_wait;
    loop {
        if call(
            client,
            Op::PrincipalDataCount,
            Value::Object(Default::default()),
        )
        .is_ok()
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(ANSWER_POLL);
    }
}

fn stop_service(probe: RegistrationProbe) -> Outcome {
    match probe() {
        None => Outcome::Failed,
        Some(port) => match port.stop(STOP_WAIT) {
            Ok(()) => Outcome::Ok,
            Err(ServiceControlError::AccessDenied) => Outcome::Forbidden,
            Err(_) => Outcome::Failed,
        },
    }
}

/// Runs the steps the machine names until it finishes or stops. The terminal
/// cannot elevate itself, so a refusal where rights are needed ends the run.
pub(super) fn drive(client: &dyn IpcClient, everyone: bool, stop: &dyn Fn() -> Outcome) -> Next {
    let mut done = Vec::new();
    loop {
        match next(false, &done) {
            Next::Run(step) => done.push((step, run_step(client, step, everyone, stop))),
            end => return end,
        }
    }
}

/// The shared per-user file both clients read goes back to a fresh install's
/// state, as the window's reset does through its preferences: the folder, the
/// chosen set, the bound files, the recorded choices and the agreement. `true`
/// when there was nothing to clear or it is cleared; a damaged file is left as
/// it is and reported.
pub(super) fn clear_user_settings(file: Option<&std::path::Path>) -> bool {
    let Some(file) = file else {
        return true;
    };
    UserSettingsStore::at(file.to_path_buf())
        .update(|settings| {
            settings.set_rules_folder("");
            settings.set_primary_file("");
            settings.set_secondary_file("");
            settings.selected_set.clear();
            settings.service_intent.clear();
            settings.accepted_eula = nrr_shared::eula::EULA_NOT_ACCEPTED;
        })
        .is_ok()
}

pub fn full_reset(
    everyone: bool,
    probe: RegistrationProbe,
    settings_file: Option<std::path::PathBuf>,
) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let settings_cleared = clear_user_settings(settings_file.as_deref());
        start_if_stopped(probe().as_deref(), client, ANSWER_WAIT);
        let end = drive(client, everyone, &|| stop_service(probe));
        Reply::new(move |app| match end {
            Next::Finish { cleared: true } if settings_cleared => {
                app.settings.reset.others = Loadable::Ready(0);
                app.settings.reset.everyone = false;
                app.settings.done(Words::Key(DONE));
            }
            Next::Finish { .. } => app.settings.refuse(Words::Key(PARTIAL)),
            Next::NeedsElevation { .. } => app.settings.failed(STOPPED, Failure::elevation()),
            Next::Run(_) => {}
        })
    })
}

#[cfg(test)]
mod tests;
