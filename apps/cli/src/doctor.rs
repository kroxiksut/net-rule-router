//! `diag doctor` — the local self-check.
//!
//! One output a person can paste into a bug report instead of three
//! screenshots. It answers the questions that decide where a problem lives:
//! is the service registered, is it running, is it the binary that shipped
//! next to this console, and does this platform support what the product
//! needs at all.
//!
//! Deliberately local: every check here works when the service is dead, which
//! is when the command gets typed. Checks that require a live service — its
//! version, its view of its own data directories — belong to the part of
//! diagnostics that talks over IPC, and are absent rather than faked.
//!
//! The judgement is a pure function over gathered facts ([`assess`]), so every
//! verdict is testable without a service manager, a privilege, or an install.

use std::path::{Path, PathBuf};

use nrr_platform_api::service_control::{ServiceControlError, ServiceControlPort};
use nrr_shared::platform_profile::PlatformProfile;
use nrr_shared::product_identity::{BinaryRole, PRODUCT_NAME};

use crate::exit;

/// How bad a single finding is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Nothing to do.
    Pass,
    /// Works, but not the way it was meant to.
    Warn,
    /// Broken; the product will not do its job in this state.
    Fail,
}

impl Level {
    fn tag(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

/// One checked thing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// What was checked.
    pub title: &'static str,
    /// How it turned out.
    pub level: Level,
    /// What was observed.
    pub detail: String,
    /// What to do about it, when there is something to do.
    pub hint: Option<String>,
}

impl Finding {
    fn pass(title: &'static str, detail: impl Into<String>) -> Self {
        Self {
            title,
            level: Level::Pass,
            detail: detail.into(),
            hint: None,
        }
    }

    fn warn(title: &'static str, detail: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            title,
            level: Level::Warn,
            detail: detail.into(),
            hint: Some(hint.into()),
        }
    }

    fn fail(title: &'static str, detail: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            title,
            level: Level::Fail,
            detail: detail.into(),
            hint: Some(hint.into()),
        }
    }
}

/// What the service manager says about the registration.
///
/// Modelled as its own enum rather than the port's `Result<Option<_>, _>` so
/// the judgement below reads as a decision table and can be exercised for
/// every outcome, including the ones that need an elevated console to produce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Registration {
    /// Registered with the operating system.
    Installed {
        /// Run state slug as the port reports it.
        run_state: &'static str,
        /// Registered start mode slug, when the manager exposes it.
        start_mode: Option<&'static str>,
        /// Registered image path, when the manager exposes it.
        binary_path: Option<PathBuf>,
    },
    /// The manager has no such service.
    NotInstalled,
    /// Reading the registration needs a privilege this console was not given.
    AccessDenied,
    /// This build has no service-manager implementation for the host OS.
    Unsupported,
    /// The manager itself failed.
    Unavailable(String),
}

/// What one of the directories the product needs looks like from here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryState {
    /// Present, and its entries can be listed from this console.
    Listable,
    /// Present, but listing it was refused. Normal for the state directory —
    /// only the service account may read it.
    Present,
    /// Nothing at that path yet.
    Missing,
    /// This platform declares no such directory.
    Undefined,
}

/// A directory the product needs, as observed — never judged here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryFact {
    /// Where it should be, when this platform declares one.
    pub path: Option<PathBuf>,
    /// What is actually there.
    pub state: DirectoryState,
}

/// Everything the checks are judged against. Gathered by [`collect`]; every
/// field is an observation, never a verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Facts {
    /// Version this console was built as.
    pub console_version: &'static str,
    /// Where this console is running from.
    pub console_path: Option<PathBuf>,
    /// The service binary shipped next to this console, when it is there.
    pub service_binary: Option<PathBuf>,
    /// Whether the application binary is shipped next to this console.
    pub gui_binary: Option<PathBuf>,
    /// Registration as the service manager reports it.
    pub registration: Registration,
    /// The OS this build targets.
    pub platform_os: &'static str,
    /// Its packet-filter backend.
    pub enforcement_backend: &'static str,
    /// Its background-service model.
    pub service_model: &'static str,
    /// Whether a privileged background service exists on this platform at all.
    pub supports_background_service: bool,
    /// Whether path comparison on this file system ignores case. An
    /// observation about the host, not a branch in the judgement.
    pub paths_are_case_insensitive: bool,
    /// The service's state directory (databases, audit trail).
    pub data_root: DirectoryFact,
    /// The service's operational-log directory.
    pub logs_dir: DirectoryFact,
    /// What the service itself said when asked. `None` when the probe was not
    /// attempted at all (no service manager on this platform).
    pub service_answer: Option<ServiceAnswer>,
}

/// The outcome of asking the running service who it is.
///
/// Kept as a fact rather than a verdict so the judgement stays pure: silence is
/// an ordinary answer here — the console is most useful when the service is
/// dead — and only [`assess`] decides what silence is worth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceAnswer {
    /// It answered, and reported this version of itself.
    Answered { service_version: String },
    /// It did not answer within the probe budget.
    Silent,
}

/// Judge gathered facts. Pure: no I/O, no privilege, no clock.
pub fn assess(facts: &Facts) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.push(Finding::pass(
        "platform",
        format!(
            "{} (services: {}, enforcement: {})",
            facts.platform_os, facts.service_model, facts.enforcement_backend
        ),
    ));

    findings.push(match &facts.console_path {
        Some(path) => Finding::pass(
            "console",
            format!("{} — {}", facts.console_version, path.display()),
        ),
        None => Finding::pass("console", facts.console_version),
    });

    findings.push(match &facts.service_binary {
        Some(path) => Finding::pass("service binary", path.display().to_string()),
        None => Finding::fail(
            "service binary",
            format!(
                "`{}` is not next to this console",
                BinaryRole::Service.host_file_name()
            ),
            "Run the console from the directory the product was installed into.",
        ),
    });

    findings.push(match &facts.gui_binary {
        Some(path) => Finding::pass("application binary", path.display().to_string()),
        None => Finding::warn(
            "application binary",
            format!(
                "`{}` is not next to this console",
                BinaryRole::Gui.host_file_name()
            ),
            "Only the console is present here; rules are edited in the application.",
        ),
    });

    match &facts.registration {
        Registration::Installed {
            run_state,
            start_mode,
            binary_path,
        } => {
            findings.push(Finding::pass("registration", "installed"));
            findings.push(run_state_finding(run_state, &console_command(facts)));
            findings.push(Finding::pass(
                "start mode",
                start_mode.unwrap_or("not reported"),
            ));
            findings.push(registered_binary_finding(facts, binary_path.as_deref()));
        }
        Registration::NotInstalled => findings.push(Finding::fail(
            "registration",
            "not installed",
            format!(
                "Install it from an elevated console: {} install",
                console_command(facts)
            ),
        )),
        Registration::AccessDenied => findings.push(Finding::warn(
            "registration",
            "could not be read without elevation",
            "Repeat this check from a console opened as administrator.",
        )),
        Registration::Unsupported => findings.push(Finding::fail(
            "registration",
            format!("no {} integration in this build", facts.service_model),
            "This platform is not supported by this build yet.",
        )),
        Registration::Unavailable(reason) => findings.push(Finding::fail(
            "registration",
            format!("the service manager did not answer: {reason}"),
            "Check that the operating system's service manager is running.",
        )),
    }

    findings.push(directory_finding(
        "state directory",
        &facts.data_root,
        "The service creates it on first start.",
    ));
    findings.push(directory_finding(
        "log directory",
        &facts.logs_dir,
        "Nothing has been logged yet; start the service and repeat this check.",
    ));

    if !facts.supports_background_service {
        findings.push(Finding::warn(
            "background service",
            "not available on this platform",
            "Policy is enforced only while the application is open.",
        ));
    }

    // What the service says about itself, when it is up. Silence is only worth
    // reporting when the service manager claims it IS running: a stopped service
    // that does not answer is not a finding, it is the same fact stated twice.
    if let Some(answer) = &facts.service_answer {
        let claims_running = matches!(
            &facts.registration,
            Registration::Installed { run_state, .. } if *run_state == "running"
        );
        match (answer, claims_running) {
            (ServiceAnswer::Answered { service_version }, _) => {
                let detail = if service_version == facts.console_version {
                    format!("{service_version} (same as this console)")
                } else {
                    format!(
                        "{service_version} — this console is {}",
                        facts.console_version
                    )
                };
                // A version difference is worth naming but is not a failure:
                // lifecycle verbs are version-neutral, and saying so beats an
                // alarm the operator cannot act on.
                findings.push(if service_version == facts.console_version {
                    Finding::pass("service answered", detail)
                } else {
                    Finding::warn(
                        "service answered",
                        detail,
                        "Console and service come from different builds; reinstall the service from this directory to match them.",
                    )
                });
            }
            (ServiceAnswer::Silent, true) => findings.push(Finding::fail(
                "service answered",
                "it is running but did not answer this console",
                // Two causes, and the operator cannot tell them apart from
                // here: the channel is not serving at all, or the running
                // service predates this console and does not admit it yet.
                // Restarting from this directory settles both.
                "Either its request channel is not serving, or the running service is an older build that does not admit this console. Restart it from this directory and repeat the check.",
            )),
            (ServiceAnswer::Silent, false) => {}
        }
    }

    findings
}

/// Report one directory. A missing one is a warning, not a failure: before the
/// first start there is nothing to find, and `doctor` exists to say so rather
/// than to fail over it.
fn directory_finding(title: &'static str, dir: &DirectoryFact, missing_hint: &str) -> Finding {
    match (&dir.path, dir.state) {
        (Some(path), DirectoryState::Listable) => Finding::pass(title, path.display().to_string()),
        (Some(path), DirectoryState::Present) => Finding::pass(
            title,
            format!("{} (listing it needs elevation)", path.display()),
        ),
        (Some(path), _) => Finding::warn(
            title,
            format!("{} does not exist", path.display()),
            missing_hint,
        ),
        (None, _) => Finding::warn(
            title,
            "this platform declares no such directory",
            "This build has no production layout for the host OS.",
        ),
    }
}

/// How the console names itself in a hint the reader is meant to retype.
///
/// A hint that is only the verb is not retypable: in PowerShell `start` is an
/// alias for `Start-Process`, so pasting it runs a different program and says
/// nothing about ours. Matches the spelling `report_failure` already uses.
fn console_command(facts: &Facts) -> String {
    facts
        .console_path
        .as_ref()
        .and_then(|p| p.file_stem())
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| BinaryRole::Console.host_file_name().to_string())
}

fn run_state_finding(run_state: &str, console: &str) -> Finding {
    match run_state {
        "running" => Finding::pass("state", "running"),
        "stopped" => Finding::warn(
            "state",
            "stopped",
            format!("Start it from an elevated console: {console} start"),
        ),
        other => Finding::pass("state", other.to_string()),
    }
}

/// Compare the binary the manager registered against the one shipped here.
///
/// This is the failure that produces the most confusing bug reports: the
/// console, the application and the registered service come from different
/// directories, so a fix that was installed is not the code that runs.
fn registered_binary_finding(facts: &Facts, registered: Option<&Path>) -> Finding {
    let Some(registered) = registered else {
        return Finding::pass("registered binary", "not reported by the service manager");
    };
    let Some(shipped) = facts.service_binary.as_deref() else {
        // Nothing to compare against; the missing-binary failure above already
        // says what to do.
        return Finding::pass("registered binary", registered.display().to_string());
    };
    if same_path(registered, shipped, facts.paths_are_case_insensitive) {
        Finding::pass("registered binary", registered.display().to_string())
    } else {
        Finding::warn(
            "registered binary",
            format!(
                "registered: {} — shipped here: {}",
                registered.display(),
                shipped.display()
            ),
            "The running service is a different copy than the one next to this \
             console. Reinstall from the directory you want to run.",
        )
    }
}

/// Path equality under the host file system's case rules.
fn same_path(a: &Path, b: &Path, case_insensitive: bool) -> bool {
    let (a, b) = (a.to_string_lossy(), b.to_string_lossy());
    if case_insensitive {
        a.eq_ignore_ascii_case(&b)
    } else {
        a == b
    }
}

/// The exit code for a finished run.
///
/// Warnings do not fail the check: `doctor` is run to look, and a console that
/// exits non-zero because the service is merely stopped would train everyone
/// to ignore its code. Failures pick the most specific code available, so a
/// script can tell "not installed" from "broken" without reading the text.
pub fn exit_code(findings: &[Finding], registration: &Registration) -> u8 {
    let worst = findings
        .iter()
        .map(|f| f.level)
        .max()
        .unwrap_or(Level::Pass);
    if worst != Level::Fail {
        return exit::SUCCESS;
    }
    match registration {
        Registration::NotInstalled => exit::NOT_INSTALLED,
        Registration::AccessDenied => exit::NEEDS_PRIVILEGE,
        Registration::Unsupported => exit::UNSUPPORTED,
        Registration::Installed { .. } | Registration::Unavailable(_) => exit::FAILED,
    }
}

/// Render the report.
pub fn render(findings: &[Finding]) -> String {
    let width = findings.iter().map(|f| f.title.len()).max().unwrap_or(0);
    let mut out = String::with_capacity(512);
    out.push_str(&format!("{PRODUCT_NAME} — installation check\n\n"));
    for finding in findings {
        out.push_str(&format!(
            "[{}] {:width$}  {}\n",
            finding.level.tag(),
            finding.title,
            finding.detail,
            width = width
        ));
        if let Some(hint) = &finding.hint {
            out.push_str(&format!("       {:width$}  -> {hint}\n", "", width = width));
        }
    }

    let (passed, warned, failed) = tally(findings);
    out.push_str(&format!(
        "\n{} passed, {}, {}.\n",
        passed,
        count_of(warned, "warning"),
        count_of(failed, "problem")
    ));
    out.push_str(
        "This report names paths and service states only — no rules, host names \
         or addresses — so it is safe to attach to a bug report.\n",
    );
    out
}

/// "1 problem" / "2 problems". English is the console's only output language,
/// so the rule is a suffix, not a locale.
fn count_of(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("{count} {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

fn tally(findings: &[Finding]) -> (usize, usize, usize) {
    let count = |level: Level| findings.iter().filter(|f| f.level == level).count();
    (count(Level::Pass), count(Level::Warn), count(Level::Fail))
}

/// Gather the facts from the host. The only impure function in this module.
pub fn collect(port: Option<&dyn ServiceControlPort>) -> Facts {
    let console_path = std::env::current_exe().ok();
    let directory = console_path.as_deref().and_then(Path::parent);
    let sibling = |role: BinaryRole| -> Option<PathBuf> {
        let candidate = directory?.join(role.host_file_name());
        candidate.exists().then_some(candidate)
    };

    let profile = PlatformProfile::current();
    let registration = read_registration(port);
    Facts {
        console_version: env!("CARGO_PKG_VERSION"),
        console_path: console_path.clone(),
        service_binary: sibling(BinaryRole::Service),
        gui_binary: sibling(BinaryRole::Gui),
        service_answer: probe_service(&registration),
        registration,
        platform_os: profile.os,
        enforcement_backend: profile.enforcement_backend,
        service_model: profile.service_model,
        supports_background_service: profile.supports.background_service,
        // Windows and macOS compare paths case-insensitively; Linux does not.
        // Gathered here so the judgement stays a pure function of its input.
        paths_are_case_insensitive: cfg!(any(windows, target_os = "macos")),
        data_root: inspect_directory(nrr_platform_api::paths::production_data_root()),
        logs_dir: inspect_directory(nrr_platform_api::paths::production_logs_dir()),
    }
}

/// Ask the running service who it is.
///
/// Attempted only when the service manager says the service is installed — a
/// probe against a service that is not there tells nobody anything and costs the
/// connect budget. The probe is a handshake, nothing more: the console declares
/// itself a console, and the answer carries the service's own version, which is
/// the one fact this command cannot get from the file system.
fn probe_service(registration: &Registration) -> Option<ServiceAnswer> {
    if !matches!(registration, Registration::Installed { .. }) {
        return None;
    }
    nrr_ipc_client::declare_client_kind(
        nrr_shared::ipc_payloads::ContractNegotiateClientKind::Console,
    );
    let client = nrr_ipc_client::ServiceIpcClient::start();
    let deadline = std::time::Instant::now() + PROBE_BUDGET;
    loop {
        match client.connection_status() {
            nrr_ipc_client::ConnectionStatus::Connected => {
                return Some(match client.negotiate_info() {
                    Some(info) if !info.service_version.is_empty() => ServiceAnswer::Answered {
                        service_version: info.service_version,
                    },
                    // Connected but the handshake carried no version: report the
                    // connection, not a version we do not have.
                    _ => ServiceAnswer::Answered {
                        service_version: "unreported".to_string(),
                    },
                });
            }
            nrr_ipc_client::ConnectionStatus::NotInstalled
            | nrr_ipc_client::ConnectionStatus::ServiceStopped => {
                return Some(ServiceAnswer::Silent)
            }
            _ => {}
        }
        if std::time::Instant::now() >= deadline {
            return Some(ServiceAnswer::Silent);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// How long the doctor waits for the service to answer. Short on purpose: this
/// command is run when something is already wrong, and a diagnostic that hangs
/// is worse than one that reports silence.
const PROBE_BUDGET: std::time::Duration = std::time::Duration::from_secs(3);

/// Look at one directory without needing the service to be alive. Listing is
/// the access that matters: the state directory is readable only by the
/// service account, so a refusal there is an observation, not a fault.
fn inspect_directory(path: Option<PathBuf>) -> DirectoryFact {
    let Some(path) = path else {
        return DirectoryFact {
            path: None,
            state: DirectoryState::Undefined,
        };
    };
    let state = if !path.is_dir() {
        DirectoryState::Missing
    } else if std::fs::read_dir(&path).is_ok() {
        DirectoryState::Listable
    } else {
        DirectoryState::Present
    };
    DirectoryFact {
        path: Some(path),
        state,
    }
}

fn read_registration(port: Option<&dyn ServiceControlPort>) -> Registration {
    let Some(port) = port else {
        return Registration::Unsupported;
    };
    match port.query() {
        Ok(Some(report)) => Registration::Installed {
            run_state: report.run_state.slug(),
            start_mode: report.start_mode.map(|m| m.slug()),
            binary_path: report.binary_path,
        },
        Ok(None) => Registration::NotInstalled,
        Err(ServiceControlError::NotInstalled) => Registration::NotInstalled,
        Err(ServiceControlError::AccessDenied) => Registration::AccessDenied,
        Err(ServiceControlError::Unsupported { .. }) => Registration::Unsupported,
        Err(other) => Registration::Unavailable(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    // Test assertions panic on infallible fixtures by design.
    #![allow(clippy::expect_used)]
    use super::*;

    use nrr_shared::product_identity::PRODUCT_NAME_UNIX;

    /// A plausible install directory, never THE install directory: `collect`
    /// reads `current_exe()` and looks beside it, so the product runs wherever
    /// it was put. Built per OS and from the identity SSOT so these fixtures
    /// carry neither a Windows-only path nor a second spelling of the name.
    fn install_dir() -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(r"C:\Program Files").join(PRODUCT_NAME)
        } else {
            PathBuf::from("/opt").join(PRODUCT_NAME_UNIX)
        }
    }

    fn installed_binary(role: BinaryRole) -> PathBuf {
        install_dir().join(role.host_file_name())
    }

    /// The same binary, but shipped somewhere else — the "a different copy is
    /// registered" case.
    fn stray_binary(role: BinaryRole) -> PathBuf {
        install_dir()
            .parent()
            .map(|p| p.join("elsewhere"))
            .unwrap_or_else(|| PathBuf::from("elsewhere"))
            .join(role.host_file_name())
    }

    fn facts(registration: Registration) -> Facts {
        Facts {
            console_version: "0.0.0-test",
            console_path: Some(installed_binary(BinaryRole::Console)),
            service_binary: Some(installed_binary(BinaryRole::Service)),
            gui_binary: Some(installed_binary(BinaryRole::Gui)),
            // The service was never asked, so there is no answer to judge.
            service_answer: None,
            registration,
            platform_os: "windows",
            enforcement_backend: "wfp",
            service_model: "scm",
            supports_background_service: true,
            paths_are_case_insensitive: true,
            data_root: DirectoryFact {
                path: Some(install_dir().join("state")),
                state: DirectoryState::Present,
            },
            logs_dir: DirectoryFact {
                path: Some(install_dir().join("logs")),
                state: DirectoryState::Listable,
            },
        }
    }

    fn installed(binary: Option<PathBuf>, run_state: &'static str) -> Registration {
        Registration::Installed {
            run_state,
            start_mode: Some("with-windows"),
            binary_path: binary,
        }
    }

    fn find<'a>(findings: &'a [Finding], title: &str) -> &'a Finding {
        findings
            .iter()
            .find(|f| f.title == title)
            .unwrap_or_else(|| panic!("no finding titled `{title}`"))
    }

    /// Every hint here is meant to be retyped, so naming only the verb is a
    /// defect: in PowerShell `start` is an alias for `Start-Process`, and a
    /// reader who pastes the hint runs a different program entirely.
    #[test]
    fn a_hint_that_asks_for_a_command_names_the_console_too() {
        for registration in [
            installed(Some(installed_binary(BinaryRole::Service)), "stopped"),
            Registration::NotInstalled,
        ] {
            for finding in assess(&facts(registration)) {
                let Some(hint) = finding.hint.as_deref() else {
                    continue;
                };
                for verb in ["start", "install", "stop", "restart", "uninstall"] {
                    if hint.contains(&format!(": {verb}")) {
                        panic!("hint `{hint}` names a bare verb; prefix it with the console");
                    }
                }
            }
        }
    }

    #[test]
    fn a_healthy_installation_reports_no_problem() {
        let facts = facts(installed(
            Some(installed_binary(BinaryRole::Service)),
            "running",
        ));
        let findings = assess(&facts);
        assert!(
            findings.iter().all(|f| f.level == Level::Pass),
            "unexpected findings: {findings:?}"
        );
        assert_eq!(exit_code(&findings, &facts.registration), exit::SUCCESS);
    }

    #[test]
    fn a_stopped_service_warns_but_does_not_fail_the_run() {
        // Someone runs `doctor` to look around. If merely being stopped
        // returned a failure code, the code would stop meaning anything.
        let facts = facts(installed(
            Some(installed_binary(BinaryRole::Service)),
            "stopped",
        ));
        let findings = assess(&facts);
        assert_eq!(find(&findings, "state").level, Level::Warn);
        assert_eq!(exit_code(&findings, &facts.registration), exit::SUCCESS);
    }

    #[test]
    fn a_service_that_is_not_installed_is_a_failure_with_its_own_code() {
        let facts = facts(Registration::NotInstalled);
        let findings = assess(&facts);
        assert_eq!(find(&findings, "registration").level, Level::Fail);
        assert_eq!(
            exit_code(&findings, &facts.registration),
            exit::NOT_INSTALLED
        );
    }

    #[test]
    fn an_unreadable_registration_asks_for_elevation_instead_of_claiming_health() {
        // Not being allowed to look is not evidence that everything is fine.
        let facts = facts(Registration::AccessDenied);
        let findings = assess(&facts);
        let registration = find(&findings, "registration");
        assert_eq!(registration.level, Level::Warn);
        assert!(registration
            .hint
            .as_ref()
            .expect("a hint")
            .contains("administrator"));
    }

    #[test]
    fn a_registration_from_another_directory_is_surfaced() {
        // The confusing case: the fix was installed, but the service that runs
        // is a different copy.
        let stray = stray_binary(BinaryRole::Service);
        let facts = facts(installed(Some(stray.clone()), "running"));
        let findings = assess(&facts);
        let finding = find(&findings, "registered binary");
        assert_eq!(finding.level, Level::Warn);
        assert!(finding.detail.contains(&stray.display().to_string()));
        assert!(finding
            .detail
            .contains(&installed_binary(BinaryRole::Service).display().to_string()));
    }

    #[test]
    fn case_differences_are_the_same_path_on_a_case_insensitive_host() {
        let shouted = installed_binary(BinaryRole::Service)
            .display()
            .to_string()
            .to_uppercase();
        let facts = facts(installed(Some(PathBuf::from(shouted)), "running"));
        assert_eq!(
            find(&assess(&facts), "registered binary").level,
            Level::Pass
        );

        // …and a different path on a host that distinguishes case.
        let mut sensitive = facts.clone();
        sensitive.paths_are_case_insensitive = false;
        assert_eq!(
            find(&assess(&sensitive), "registered binary").level,
            Level::Warn
        );
    }

    #[test]
    fn a_missing_service_binary_is_a_failure() {
        let mut facts = facts(installed(None, "running"));
        facts.service_binary = None;
        let findings = assess(&facts);
        assert_eq!(find(&findings, "service binary").level, Level::Fail);
        assert_eq!(exit_code(&findings, &facts.registration), exit::FAILED);
    }

    #[test]
    fn a_state_directory_that_cannot_be_listed_still_passes() {
        // Only the service account may read it; a console that cannot list it
        // has learned nothing bad. Saying why beats a permanent warning.
        let findings = assess(&facts(installed(
            Some(installed_binary(BinaryRole::Service)),
            "running",
        )));
        let finding = find(&findings, "state directory");
        assert_eq!(finding.level, Level::Pass);
        assert!(
            finding.detail.contains("needs elevation"),
            "detail was: {}",
            finding.detail
        );
    }

    #[test]
    fn a_missing_log_directory_warns_without_failing_the_run() {
        // Before the first start there is nothing to find. `doctor` is run to
        // look; exiting non-zero over an empty install trains everyone to
        // ignore the code.
        let mut facts = facts(installed(
            Some(installed_binary(BinaryRole::Service)),
            "running",
        ));
        facts.logs_dir.state = DirectoryState::Missing;
        let findings = assess(&facts);
        assert_eq!(find(&findings, "log directory").level, Level::Warn);
        assert_eq!(exit_code(&findings, &facts.registration), exit::SUCCESS);
    }

    #[test]
    fn a_service_that_is_stopped_and_silent_is_not_reported_twice() {
        // "Stopped" is already a finding of its own. Adding "and it did not
        // answer" says nothing new and makes the report look worse than it is.
        let mut facts = facts(installed(
            Some(installed_binary(BinaryRole::Service)),
            "stopped",
        ));
        facts.service_answer = Some(ServiceAnswer::Silent);
        let findings = assess(&facts);
        assert!(findings.iter().all(|f| f.title != "service answered"));
    }

    #[test]
    fn a_running_service_that_does_not_answer_is_a_failure() {
        // The process is up but its request channel is not serving — the state
        // the console exists to distinguish from "not running".
        let mut facts = facts(installed(
            Some(installed_binary(BinaryRole::Service)),
            "running",
        ));
        facts.service_answer = Some(ServiceAnswer::Silent);
        let findings = assess(&facts);
        assert_eq!(find(&findings, "service answered").level, Level::Fail);
        assert_eq!(exit_code(&findings, &facts.registration), exit::FAILED);
    }

    #[test]
    fn a_version_difference_warns_but_does_not_fail() {
        // Lifecycle verbs are version-neutral, so a mismatch is worth naming and
        // not worth failing over.
        let mut facts = facts(installed(
            Some(installed_binary(BinaryRole::Service)),
            "running",
        ));
        facts.service_answer = Some(ServiceAnswer::Answered {
            service_version: "9.9.9-other".to_string(),
        });
        let findings = assess(&facts);
        assert_eq!(find(&findings, "service answered").level, Level::Warn);
        assert_eq!(exit_code(&findings, &facts.registration), exit::SUCCESS);

        facts.service_answer = Some(ServiceAnswer::Answered {
            service_version: facts.console_version.to_string(),
        });
        let findings = assess(&facts);
        assert_eq!(find(&findings, "service answered").level, Level::Pass);
    }

    #[test]
    fn a_platform_with_no_declared_directories_says_so_instead_of_naming_a_path() {
        let mut facts = facts(installed(
            Some(installed_binary(BinaryRole::Service)),
            "running",
        ));
        facts.data_root = DirectoryFact {
            path: None,
            state: DirectoryState::Undefined,
        };
        let findings = assess(&facts);
        let finding = find(&findings, "state directory");
        assert_eq!(finding.level, Level::Warn);
        assert!(
            finding.detail.contains("no such directory"),
            "detail was: {}",
            finding.detail
        );
    }

    #[test]
    fn a_platform_without_an_implementation_says_so_rather_than_reporting_nothing() {
        let mut facts = facts(Registration::Unsupported);
        facts.platform_os = "macos";
        facts.service_model = "launchd";
        let findings = assess(&facts);
        assert_eq!(find(&findings, "registration").level, Level::Fail);
        assert_eq!(exit_code(&findings, &facts.registration), exit::UNSUPPORTED);
    }

    #[test]
    fn the_report_prints_every_finding_and_its_hint() {
        let facts = facts(Registration::NotInstalled);
        let findings = assess(&facts);
        let text = render(&findings);
        for finding in &findings {
            assert!(
                text.contains(finding.title),
                "report omits `{}`",
                finding.title
            );
            if let Some(hint) = &finding.hint {
                assert!(
                    text.contains(hint),
                    "report omits the hint for `{}`",
                    finding.title
                );
            }
        }
        assert!(text.contains("problem."), "summary line was wrong: {text}");
    }

    #[test]
    fn the_summary_counts_agree_with_the_number_they_precede() {
        assert_eq!(count_of(0, "problem"), "0 problems");
        assert_eq!(count_of(1, "problem"), "1 problem");
        assert_eq!(count_of(2, "warning"), "2 warnings");
    }

    #[test]
    fn the_report_promises_only_what_it_prints() {
        // The privacy line is the reason people paste this into an issue; it
        // must stay true, so the facts the checks are built from carry no
        // hostnames or addresses in the first place.
        let facts = facts(installed(
            Some(installed_binary(BinaryRole::Service)),
            "running",
        ));
        let text = render(&assess(&facts));
        assert!(text.contains("no rules, host names"));
    }
}
