//! A rule set loaded is a rule set applied, as in the window: a stopped
//! service is started first so the set reaches it in the same action, and the
//! outcome is a line in the feed, where the window shows a message box.

use std::time::{Duration, Instant};

use nrr_ipc_client::{ipc_operation_timeout, IpcClient};
use nrr_platform_api::service_control::{ServiceControlError, ServiceControlPort, ServiceRunState};
use nrr_shared::display_text::display_text;
use nrr_shared::ipc::IpcOperationName as Op;
use serde_json::Value;

use crate::backend::{Job, RegistrationProbe, Reply};
use crate::i18n::{key, Key, Plural, Texts};
use crate::state::{AppState, Effect, Notice, NoticeLevel};

pub const APPLIED_TITLE: Key = key("dialog.rule-set-applied.title", "Rule set applied");
pub const APPLIED_BODY: Plural = Plural {
    stem: "dialog.rule-set-applied.body.",
    one: "«{name}»: {count} rule is now in use.",
    other: "«{name}»: {count} rules are now in use.",
};
pub const NOT_APPLIED_TITLE: Key = key("dialog.rule-set-not-applied.title", "Rule set not applied");
/// Not the window's wording: this terminal keeps no parked import for the
/// service to pick up later, so it says how to get the set in force.
pub const SERVICE_DOWN: Key = key(
    "tui.rule-set.not-applied",
    "«{name}»: the service could not be started, so these rules are not in use yet ({reason}). Start the service in Settings, then load the set again.",
);
pub const SILENT: Key = key(
    "status.service-did-not-answer",
    "The service did not start answering in time.",
);
pub const NO_MANAGER: Key = key(
    "tui.settings.service.no-manager",
    "This system has no service manager this program can ask.",
);
pub const NOT_INSTALLED: Key = key("settings.service.status.not-installed", "Not installed");
pub const NO_RIGHTS: Key = key(
    "tui.rule-set.start-needs-rights",
    "starting the service needs administrator rights",
);
pub const REFUSED: Key = key(
    "tui.rule-set.not-applied-reason",
    "«{name}»: these rules are not in use ({reason}). Load the set again from the Rules screen.",
);
pub const PROTECTION_NOT_SAVED: Key = key(
    "tui.rule-set.not-applied-protection",
    "«{name}»: these rules are not in use, because the leak protection chosen with them could not be saved. Set it in Connections, then load the set again from the Rules screen.",
);

#[cfg(test)]
pub fn keys() -> Vec<Key> {
    vec![
        APPLIED_TITLE,
        NOT_APPLIED_TITLE,
        SERVICE_DOWN,
        SILENT,
        NO_MANAGER,
        NOT_INSTALLED,
        NO_RIGHTS,
        REFUSED,
        PROTECTION_NOT_SAVED,
        key("dialog.rule-set-applied.body.one", ""),
        key("dialog.rule-set-applied.body.other", ""),
    ]
}

/// How long a start may take, and how long the started service gets to answer.
const START_WAIT: Duration = Duration::from_secs(30);
const ANSWER_WAIT: Duration = Duration::from_secs(15);
const ANSWER_POLL: Duration = Duration::from_millis(500);

/// A set's name as the user picked it: a locale key with the folder as its
/// fallback for a shipped set, or the plain name of one of the user's own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetName {
    key: String,
    fallback: String,
}

impl SetName {
    pub fn keyed(key: String, fallback: String) -> Self {
        Self { key, fallback }
    }

    /// A name read from disk: shown escaped.
    pub fn plain(name: &str) -> Self {
        Self {
            key: String::new(),
            fallback: name.to_owned(),
        }
    }

    /// The folder of a set's two files, else the file.
    pub fn of_path(path: &std::path::Path) -> Self {
        let file = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let is_set_file = file.eq_ignore_ascii_case("rules_primary.txt")
            || file.eq_ignore_ascii_case("rules_secondary.txt");
        let folder = path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str());
        match folder {
            Some(folder) if is_set_file => Self::plain(folder),
            _ => Self::plain(file),
        }
    }

    pub fn resolve(&self, texts: &Texts) -> String {
        if self.key.is_empty() {
            display_text(&self.fallback).into_owned()
        } else {
            texts.dynamic(&self.key, &self.fallback)
        }
    }
}

/// Why the service could not be brought up for the load.
#[derive(Debug)]
pub enum StartFailure {
    NoManager,
    NotInstalled,
    Control(ServiceControlError),
    Silent,
}

impl StartFailure {
    fn words(&self, texts: &Texts) -> String {
        match self {
            Self::NoManager => texts.get(NO_MANAGER),
            Self::NotInstalled => texts.get(NOT_INSTALLED),
            Self::Control(ServiceControlError::AccessDenied) => texts.get(NO_RIGHTS),
            Self::Control(error) => error.to_string(),
            Self::Silent => texts.get(SILENT),
        }
    }
}

/// Why a set the setup chose was not applied as it closed.
#[derive(Debug)]
pub enum Refusal {
    /// The service's error code.
    Code(String),
    /// The protection chosen with the set could not be saved; rules never run
    /// without it.
    ProtectionNotSaved,
    NoService,
}

#[derive(Debug)]
enum Told {
    Applied { name: SetName, count: usize },
    NotApplied { name: SetName, why: StartFailure },
    Refused { name: SetName, why: Refusal },
}

#[derive(Debug, Default)]
pub struct RuleSetLoadState {
    /// Outcomes not yet told; announced on the next tick with texts in hand.
    unannounced: Vec<Told>,
}

pub fn applied(app: &mut AppState, name: SetName, count: usize) {
    app.rule_set_load
        .unannounced
        .push(Told::Applied { name, count });
}

pub fn not_applied(app: &mut AppState, name: SetName, why: StartFailure) {
    app.rule_set_load
        .unannounced
        .push(Told::NotApplied { name, why });
}

pub fn refused(app: &mut AppState, name: SetName, why: Refusal) {
    app.rule_set_load
        .unannounced
        .push(Told::Refused { name, why });
}

pub fn announce(app: &mut AppState, texts: &Texts, now: Instant) -> Vec<Effect> {
    let told = std::mem::take(&mut app.rule_set_load.unannounced);
    let mut effects = Vec::new();
    for item in told {
        let notice = match item {
            Told::Applied { name, count } => Notice::new(
                NoticeLevel::Info,
                texts.get(APPLIED_TITLE),
                texts
                    .counted(APPLIED_BODY, count)
                    .replace("{name}", &name.resolve(texts)),
            ),
            Told::NotApplied { name, why } => Notice::new(
                NoticeLevel::Warning,
                texts.get(NOT_APPLIED_TITLE),
                texts.fill(
                    SERVICE_DOWN,
                    &[("name", name.resolve(texts)), ("reason", why.words(texts))],
                ),
            ),
            Told::Refused { name, why } => {
                let name = name.resolve(texts);
                let body = match why {
                    Refusal::Code(code) => texts.fill(
                        REFUSED,
                        &[
                            ("name", name),
                            ("reason", crate::screens::binding::error_text(&code, texts)),
                        ],
                    ),
                    Refusal::NoService => texts.fill(
                        REFUSED,
                        &[
                            ("name", name),
                            (
                                "reason",
                                crate::screens::binding::error_text(
                                    "transport-disconnected",
                                    texts,
                                ),
                            ),
                        ],
                    ),
                    Refusal::ProtectionNotSaved => {
                        texts.fill(PROTECTION_NOT_SAVED, &[("name", name)])
                    }
                };
                Notice::new(NoticeLevel::Warning, texts.get(NOT_APPLIED_TITLE), body)
            }
        };
        effects.extend(app.post(notice, Some(now)));
    }
    effects
}

/// Brings a stopped service up and waits until it answers. A running or
/// starting service is only waited for.
pub fn start_service(
    port: Option<&dyn ServiceControlPort>,
    client: &dyn IpcClient,
    answer_wait: Duration,
) -> Result<(), StartFailure> {
    let port = port.ok_or(StartFailure::NoManager)?;
    match port.query() {
        Ok(None) | Err(ServiceControlError::NotInstalled) => {
            return Err(StartFailure::NotInstalled)
        }
        Ok(Some(report)) if report.run_state == ServiceRunState::Stopped => {
            port.start(START_WAIT).map_err(StartFailure::Control)?;
        }
        Ok(Some(_)) => {}
        Err(error) => return Err(StartFailure::Control(error)),
    }
    // Running to the service manager is not yet listening on its channel.
    client.force_reconnect();
    let deadline = Instant::now() + answer_wait;
    let op = Op::PrincipalDataCount;
    loop {
        if client
            .call(
                op,
                Value::Object(Default::default()),
                ipc_operation_timeout(op),
            )
            .is_ok()
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(StartFailure::Silent);
        }
        std::thread::sleep(ANSWER_POLL);
    }
}

/// The job that starts the service, then hands the outcome to `then`.
pub fn start_then(
    probe: RegistrationProbe,
    then: impl FnOnce(&mut AppState, Result<(), StartFailure>) + Send + 'static,
) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let result = start_service(probe().as_deref(), client, ANSWER_WAIT);
        Reply::new(move |app| then(app, result))
    })
}

#[cfg(test)]
mod tests;
