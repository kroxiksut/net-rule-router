//! The full reset: the window's steps, in the order `nrr-client-logic` gives
//! them, over the same operations. Whatever needs the window's own files (the
//! saved comments) is not this terminal's to clear and is skipped; whatever
//! needs administrator rights is refused with how to start the terminal with
//! them, and then the reset stops before it touches the service. It ends with
//! the service restarted on the cleared state, as after a fresh install.

use std::time::{Duration, Instant};

use nrr_client_logic::full_reset::{next, Next, Outcome, Step};
use nrr_ipc_client::{ipc_operation_timeout, IpcClient};
use nrr_platform_api::service_control::{ServiceControlError, ServiceControlPort, ServiceRunState};
use nrr_shared::ipc::IpcOperationName as Op;
use nrr_shared::ipc_payloads::{
    LogsClearRequest, PrincipalDataCountResponse, PrincipalDataPurgeRequest,
};
use nrr_shared::user_settings::UserSettingsStore;
use serde_json::Value;

use super::items::Words;
use super::{Failure, Input, Loadable};
use crate::backend::{Job, RegistrationProbe, Reply};
use crate::i18n::{key, Key};
use crate::state::AppState;

pub const TITLE: Key = key("dialog.full-reset.title", "Full reset");
pub const BODY: Key = key(
    "dialog.full-reset.body",
    "This resets ALL application settings to defaults, deletes the rules the service keeps for you (back to a post-install state), wipes saved comments and logs, and restarts the background service clean, so routing and protection start again as after a fresh install. Your own rules files on disk are left untouched, and the background service is NOT uninstalled. This cannot be undone.",
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
    "Full reset is done and the service is running again on the cleared state. Close this terminal and any NetRuleRouter window, then start again.",
);
pub const RESTART_FAILED: Key = key(
    "tui.settings.reset.restart-failed",
    "Full reset is done, but the service did not start again, so routing and protection are off until it runs: {error}. Start it in Settings.",
);
pub const SILENT: Key = key(
    "status.service-did-not-answer",
    "The service did not start answering in time.",
);
pub const PARTIAL: Key = key(
    "dialog.full-reset-done.service-warn",
    "Note: some service-side data could not be cleared (administrator approval may be required, or a temporary error occurred). Re-run the reset.",
);
pub const STOPPED: Key = key(
    "tui.settings.reset.needs-elevation",
    "Full reset stopped before the rules were cleared and the service was restarted: {error}",
);

#[cfg(test)]
pub fn keys() -> Vec<Key> {
    vec![
        TITLE,
        BODY,
        OTHERS,
        SCOPE,
        MINE,
        EVERYONE,
        RUN,
        RUNNING,
        DONE,
        RESTART_FAILED,
        SILENT,
        PARTIAL,
        STOPPED,
    ]
}

/// A service restart that has not finished in this time is reported as failed.
const RESTART_WAIT: Duration = Duration::from_secs(30);
/// How long a service started for the reset gets to come up and answer.
const START_WAIT: Duration = Duration::from_secs(30);
const ANSWER_WAIT: Duration = Duration::from_secs(15);
const ANSWER_POLL: Duration = Duration::from_millis(500);

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

fn run_step(
    client: &dyn IpcClient,
    step: Step,
    everyone: bool,
    restart: &dyn Fn() -> Outcome,
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
        Step::RestartService => restart(),
    }
}

/// A stopped service answers none of the steps, so the reset would only say
/// what it could not clear: it is started first, and the last step restarts
/// it. A start that fails or is refused leaves the steps to report that.
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
    answers(client, answer_wait)
}

/// Running to the service manager is not yet listening on its channel.
fn answers(client: &dyn IpcClient, answer_wait: Duration) -> bool {
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

/// Why the service did not come back after the reset.
#[derive(Debug)]
pub(super) enum RestartFailure {
    NoManager,
    Control(ServiceControlError),
    Silent,
}

impl RestartFailure {
    fn outcome(&self) -> Outcome {
        match self {
            Self::Control(ServiceControlError::AccessDenied) => Outcome::Forbidden,
            _ => Outcome::Failed,
        }
    }

    fn words(&self) -> Words {
        let reason = match self {
            Self::NoManager => Words::Key(super::text::SERVICE_NO_MANAGER),
            Self::Control(ServiceControlError::AccessDenied) => {
                return Words::Failed(RESTART_FAILED, Failure::elevation())
            }
            Self::Control(error) => Words::Raw(error.to_string()),
            Self::Silent => Words::Key(SILENT),
        };
        Words::Nested(RESTART_FAILED, vec![("error", reason)])
    }
}

/// The last step: stop and start in one go, then wait until the service
/// answers on the cleared state.
pub(super) fn restart_service(
    port: Option<&dyn ServiceControlPort>,
    client: &dyn IpcClient,
    answer_wait: Duration,
) -> Result<(), RestartFailure> {
    let port = port.ok_or(RestartFailure::NoManager)?;
    port.restart(RESTART_WAIT)
        .map_err(RestartFailure::Control)?;
    if answers(client, answer_wait) {
        Ok(())
    } else {
        Err(RestartFailure::Silent)
    }
}

/// Runs the steps the machine names until it finishes or stops. The terminal
/// cannot elevate itself, so a refusal where rights are needed ends the run.
/// Clearing every user's data is the step that needs them, so it runs first:
/// refused, it stops the reset before the logs or anything else are erased.
pub(super) fn drive(client: &dyn IpcClient, everyone: bool, restart: &dyn Fn() -> Outcome) -> Next {
    let mut purged = None;
    if everyone {
        let outcome = run_step(client, Step::PurgePrincipalData, true, restart);
        if outcome == Outcome::Forbidden {
            return Next::NeedsElevation {
                step: Step::PurgePrincipalData,
            };
        }
        purged = Some(outcome);
    }
    let mut done = Vec::new();
    loop {
        match next(false, &done) {
            Next::Run(step) => {
                let outcome = match (step, purged) {
                    (Step::PurgePrincipalData, Some(outcome)) => outcome,
                    _ => run_step(client, step, everyone, restart),
                };
                done.push((step, outcome));
            }
            end => return end,
        }
    }
}

/// The shared per-user file both clients read goes back to a fresh install's
/// state, as the window's reset does through its preferences: the folder, the
/// chosen set, the bound files, the recorded choices, the answer to the rule-set
/// offer and the agreement. `true`
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
            settings.rule_set_offer_answered = false;
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
        start_if_stopped(probe().as_deref(), client, ANSWER_WAIT);
        let failure = std::cell::RefCell::new(None);
        let end = drive(client, everyone, &|| match restart_service(
            probe().as_deref(),
            client,
            ANSWER_WAIT,
        ) {
            Ok(()) => Outcome::Ok,
            Err(why) => {
                let outcome = why.outcome();
                *failure.borrow_mut() = Some(why);
                outcome
            }
        });
        let failure = failure.into_inner();
        // The local file goes last: a reset stopped for want of rights keeps
        // the bound files and the choices a reinstalled service is restored from.
        let settings_cleared =
            matches!(end, Next::Finish { .. }) && clear_user_settings(settings_file.as_deref());
        Reply::new(move |app| match end {
            Next::Finish { cleared: true, .. } if settings_cleared => {
                app.settings.reset.others = Loadable::Ready(0);
                app.settings.reset.everyone = false;
                match failure {
                    None => app.settings.done(Words::Key(DONE)),
                    Some(why) => app.settings.refuse(why.words()),
                }
            }
            Next::Finish { .. } => app.settings.refuse(Words::Key(PARTIAL)),
            Next::NeedsElevation { .. } => app.settings.failed(STOPPED, Failure::elevation()),
            Next::Run(_) => {}
        })
    })
}

#[cfg(test)]
mod tests;
