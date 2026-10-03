//! `local.service-control` on Linux.
//!
//! The service is a systemd unit. Lifecycle verbs go to `systemctl` as this
//! user: systemd asks polkit, and the session's agent shows the prompt.
//! Registration verbs run the installed daemon's own verb under `pkexec`, the
//! same implementation the console and the install scripts use. The daemon is
//! always the installed copy, located here: a path from the request is never
//! run, and a build-tree copy under `/home` could not run as the service anyway.

#![cfg(target_os = "linux")]

use std::path::Path;
use std::time::Duration;

use nrr_platform_linux::systemd::{installed_daemon_path, SYSTEMD_UNIT_NAME};

/// Long enough for the user to read and answer an authentication prompt.
const PROMPT_BUDGET: Duration = Duration::from_secs(90);

/// What an action runs.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    /// `systemctl <verb> <unit>`.
    Systemctl(&'static str),
    /// `pkexec <installed daemon> <verb>`.
    Daemon(&'static str),
}

/// The step for a GUI action, `None` for one this platform does not carry out.
#[must_use]
pub fn plan(action: &str) -> Option<Step> {
    match action {
        "start" => Some(Step::Systemctl("start")),
        "stop" => Some(Step::Systemctl("stop")),
        "restart" => Some(Step::Systemctl("restart")),
        "set-start-auto" => Some(Step::Systemctl("enable")),
        // The installed copy is the only one there is, so a re-registration
        // is an install of it.
        "install" | "reinstall" => Some(Step::Daemon("install")),
        "uninstall" => Some(Step::Daemon("uninstall")),
        "cleanup" => Some(Step::Daemon("cleanup")),
        // Nothing on Linux starts the service with the app, so a unit that
        // does not start at boot would never run.
        _ => None,
    }
}

/// Why an action failed, as the GUI's error code and English detail.
#[derive(Debug, PartialEq, Eq)]
pub struct Refusal {
    pub code: &'static str,
    pub message: String,
}

impl Refusal {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Carry out `action`. `Ok` once the step has finished successfully.
pub fn run(action: &str) -> Result<serde_json::Value, Refusal> {
    let step = plan(action).ok_or_else(|| {
        Refusal::new(
            "unsupported-platform",
            format!("`{action}` is not available for the service on this system"),
        )
    })?;
    let daemon = installed_daemon_path();
    let (program, args): (&str, Vec<String>) = match &step {
        Step::Systemctl(verb) => (
            "systemctl",
            vec![(*verb).to_string(), SYSTEMD_UNIT_NAME.to_string()],
        ),
        Step::Daemon(verb) => {
            if !is_executable(&daemon) {
                return Err(Refusal::new(
                    "service-not-installed",
                    format!(
                        "{} is not installed; install the package first",
                        daemon.display()
                    ),
                ));
            }
            (
                nrr_platform_linux::elevation::PKEXEC_PROGRAM,
                vec![daemon.to_string_lossy().into_owned(), (*verb).to_string()],
            )
        }
    };
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = nrr_platform_linux::command::output_with_timeout(program, &borrowed, PROMPT_BUDGET)
        .map_err(|e| Refusal::new("service-control-failed", format!("{program}: {e}")))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    classify(&step, out.status.code(), &stderr).map(|()| serde_json::json!({ "action": action }))
}

/// The verdict on a finished step.
fn classify(step: &Step, code: Option<i32>, stderr: &str) -> Result<(), Refusal> {
    if code == Some(0) {
        return Ok(());
    }
    let declined = match step {
        // Dismissed (126) or not authorized (127), per pkexec(1).
        Step::Daemon(_) => matches!(
            nrr_platform_linux::elevation::classify_pkexec_exit(code),
            nrr_platform_linux::elevation::ElevationOutcome::Declined
        ),
        // systemctl reports a refused or cancelled authorization in words; the
        // C locale `output_with_timeout` sets keeps them English.
        Step::Systemctl(_) => {
            let lower = stderr.to_ascii_lowercase();
            lower.contains("access denied")
                || lower.contains("authentication")
                || lower.contains("not authorized")
        }
    };
    if declined {
        return Err(Refusal::new(
            "uac-declined",
            "Administrator approval is required for this service action.",
        ));
    }
    let detail = stderr
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("no detail");
    Err(Refusal::new(
        "service-control-failed",
        format!("exit {}: {detail}", code.unwrap_or(-1)),
    ))
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_goes_to_systemd_and_registration_to_the_daemon() {
        assert_eq!(plan("start"), Some(Step::Systemctl("start")));
        assert_eq!(plan("restart"), Some(Step::Systemctl("restart")));
        assert_eq!(plan("set-start-auto"), Some(Step::Systemctl("enable")));
        assert_eq!(plan("install"), Some(Step::Daemon("install")));
        assert_eq!(plan("reinstall"), Some(Step::Daemon("install")));
        assert_eq!(plan("cleanup"), Some(Step::Daemon("cleanup")));
    }

    /// Nothing on Linux would start a unit that does not start at boot.
    #[test]
    fn an_action_this_platform_cannot_honour_is_refused() {
        assert_eq!(plan("set-start-demand"), None);
        assert_eq!(plan("anything"), None);
        let refusal = run("set-start-demand").expect_err("refused");
        assert_eq!(refusal.code, "unsupported-platform");
    }

    #[test]
    fn a_closed_or_refused_prompt_reads_as_declined() {
        let daemon = Step::Daemon("install");
        for code in [126, 127] {
            assert_eq!(
                classify(&daemon, Some(code), "")
                    .expect_err("declined")
                    .code,
                "uac-declined"
            );
        }
        let unit = Step::Systemctl("stop");
        assert_eq!(
            classify(&unit, Some(1), "Failed to stop x.service: Access denied\n")
                .expect_err("declined")
                .code,
            "uac-declined"
        );
    }

    #[test]
    fn any_other_failure_names_its_last_line() {
        let refusal = classify(
            &Step::Daemon("install"),
            Some(1),
            "first\ninstall failed: unit dir unwritable\n\n",
        )
        .expect_err("failed");
        assert_eq!(refusal.code, "service-control-failed");
        assert!(refusal
            .message
            .ends_with("install failed: unit dir unwritable"));
        assert!(classify(&Step::Systemctl("start"), Some(0), "").is_ok());
    }
}
