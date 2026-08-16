//! The systemd implementation of
//! [`nrr_platform_api::service_control::ServiceControlPort`] — the Linux
//! counterpart of `nrr_platform_windows::service_control::WindowsServiceControl`.
//!
//! The decision of what to write and what to run is the pure plan in
//! [`crate::systemd`]; this module is what performs it and what translates
//! systemd's answers back into the port's neutral vocabulary. Both halves of
//! that translation are pure functions ([`parse_show_output`],
//! [`classify_command_failure`]), so the interesting cases — a unit that does
//! not exist, a caller without root, a unit installed but not enabled — are
//! unit-tested against captured `systemctl` output rather than against a live
//! systemd.
//!
//! Side effects go through the [`SystemdOps`] seam, so install, uninstall,
//! start, stop and query are all exercised end to end with a recording double.
//! [`FsOps`] — a filesystem write, an unlink, a symlink and a spawn — is the
//! only part that needs a real host.

#![cfg(target_os = "linux")]

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nrr_platform_api::service_control::{
    ServiceControlError, ServiceControlPort, ServiceInstallReport, ServiceInstallSpec,
    ServiceRunState, ServiceStartMode, ServiceStatusReport, ServiceUninstallReport,
    ServiceUninstallSpec,
};

use crate::systemd::{
    log_dir, plan_install, plan_uninstall, state_dir, SystemdInstallPlan, SystemdServiceConfig,
    SystemdUninstallPlan, UnitActivation, SYSTEMD_UNIT_NAME,
};

/// The privileged watchdog contract: the daemon must ping `WATCHDOG=1` at least
/// this often, or systemd restarts it. The daemon derives its ping interval
/// from `$WATCHDOG_USEC`, which systemd sets from this value.
const WATCHDOG_SEC: u32 = 30;

/// How often the state after `start` / `stop` is re-checked while waiting.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

// ── The side-effect seam ─────────────────────────────────────────────────────

/// What a command did. A non-zero exit is data, not an error: `is-active`
/// answers "no" with exit code 3, and reading that as a failure would turn
/// every stopped service into a broken one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandOutcome {
    /// Process exit code, or `-1` when the process was killed by a signal.
    pub exit_code: i32,
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error — the text failures are classified from.
    pub stderr: String,
}

impl CommandOutcome {
    fn succeeded(&self) -> bool {
        self.exit_code == 0
    }
}

/// The host operations install / uninstall / start / stop / query need.
///
/// Everything here is a side effect; nothing here decides anything. That split
/// is what lets the port's whole behaviour be tested without systemd.
pub trait SystemdOps {
    /// Write `contents` to `path` (creating parent directories) with `mode`.
    fn write_file(&self, path: &Path, contents: &str, mode: u32) -> io::Result<()>;
    /// Remove `path`. Absence is success, so uninstall is idempotent.
    fn remove_file(&self, path: &Path) -> io::Result<()>;
    /// Remove a directory tree. Absence is success.
    fn remove_dir_all(&self, path: &Path) -> io::Result<()>;
    /// Point `link` at `target`, replacing a link already there so a repeat
    /// install is not an error.
    fn symlink(&self, target: &Path, link: &Path) -> io::Result<()>;
    /// Run `argv` (no shell) and capture what it said.
    fn run(&self, argv: &[String]) -> io::Result<CommandOutcome>;
}

/// The real implementation: filesystem writes and `systemctl` spawns.
pub struct FsOps;

impl SystemdOps for FsOps {
    fn write_file(&self, path: &Path, contents: &str, mode: u32) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, contents)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            // Also covers the alias symlink: this unlinks the link itself,
            // never what it points at.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn remove_dir_all(&self, path: &Path) -> io::Result<()> {
        match std::fs::remove_dir_all(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn symlink(&self, target: &Path, link: &Path) -> io::Result<()> {
        // `symlink(2)` refuses an existing path and a re-install must not fail,
        // so the old link is unlinked first.
        match std::fs::remove_file(link) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        if let Some(parent) = link.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::os::unix::fs::symlink(target, link)
    }

    fn run(&self, argv: &[String]) -> io::Result<CommandOutcome> {
        let Some((exe, rest)) = argv.split_first() else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty command"));
        };
        let out = std::process::Command::new(exe).args(rest).output()?;
        Ok(CommandOutcome {
            exit_code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

// ── Translating systemd's answers ────────────────────────────────────────────

/// The subset of `systemctl show` properties this port reads.
const SHOW_PROPERTIES: &str = "LoadState,ActiveState,UnitFileState,ExecStart";

/// What `systemctl show` said, in the port's vocabulary. `None` means the unit
/// is not known to systemd.
pub type ShowFacts = Option<ServiceStatusReport>;

/// Parse `systemctl show --property=…` output.
///
/// The format is one `Key=value` per line, and systemd answers for an unknown
/// unit too — with `LoadState=not-found`. That distinction is the whole reason
/// this is parsed rather than inferred from an exit code.
pub fn parse_show_output(output: &str) -> ShowFacts {
    let mut load_state = "";
    let mut active_state = "";
    let mut unit_file_state = "";
    let mut exec_start = "";
    for line in output.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "LoadState" => load_state = value.trim(),
            "ActiveState" => active_state = value.trim(),
            "UnitFileState" => unit_file_state = value.trim(),
            // `ExecStart` may repeat; the first line is the one that runs.
            "ExecStart" if exec_start.is_empty() => exec_start = value.trim(),
            _ => {}
        }
    }

    if load_state.is_empty() || load_state == "not-found" {
        return None;
    }

    Some(ServiceStatusReport {
        run_state: run_state_from_active_state(active_state),
        start_mode: start_mode_from_unit_file_state(unit_file_state),
        binary_path: exec_start_binary(exec_start),
        // TODO: read the process start time. systemd carries it as
        // `ExecMainStartTimestamp`, but its default rendering is a localised
        // human string whose parsing differs across systemd versions; the
        // `--timestamp=unix` form that would make this trivial is not old
        // enough to rely on yet.
        running_since: None,
    })
}

/// Map systemd's `ActiveState` onto the neutral run state.
fn run_state_from_active_state(active_state: &str) -> ServiceRunState {
    match active_state {
        "active" => ServiceRunState::Running,
        "activating" => ServiceRunState::StartPending,
        "deactivating" => ServiceRunState::StopPending,
        // `failed` is a stopped service that stopped badly. The port models run
        // state, not why it is not running; the reason belongs to diagnostics.
        "inactive" | "failed" => ServiceRunState::Stopped,
        _ => ServiceRunState::Other,
    }
}

/// Map systemd's `UnitFileState` onto the neutral start mode.
///
/// "Enabled" is exactly "starts with the operating system". Everything that is
/// installed but not wired into the boot target is "starts when asked" —
/// including `static` and `masked`, which cannot be enabled at all.
fn start_mode_from_unit_file_state(unit_file_state: &str) -> Option<ServiceStartMode> {
    match unit_file_state {
        "enabled" | "enabled-runtime" | "alias" | "indirect" => Some(ServiceStartMode::WithWindows),
        "disabled" | "static" | "masked" | "masked-runtime" | "linked" | "linked-runtime" => {
            Some(ServiceStartMode::OnAppLaunch)
        }
        _ => None,
    }
}

/// Extract the binary from an `ExecStart` property value.
///
/// systemd renders it as a structured record —
/// `{ path=/usr/lib/netrulerouter/nrr-serviced ; argv[]=… ; ignore_errors=no … }` —
/// so the executable is the `path=` field, not the whole string.
fn exec_start_binary(exec_start: &str) -> Option<PathBuf> {
    let after = exec_start.split("path=").nth(1)?;
    let path = after.split(';').next()?.trim();
    if path.is_empty() {
        return None;
    }
    Some(PathBuf::from(path))
}

/// Turn a failed command into the port's error taxonomy.
///
/// systemd reports privilege failures as text (polkit's "Interactive
/// authentication required" when there is no agent, a plain permission error
/// when writing to `/etc`), so the classification is a text match — kept in one
/// pure function with its samples in the tests below rather than scattered
/// across call sites.
pub fn classify_command_failure(outcome: &CommandOutcome, argv: &[String]) -> ServiceControlError {
    let text = format!("{} {}", outcome.stdout, outcome.stderr).to_ascii_lowercase();
    if text.contains("interactive authentication required")
        || text.contains("access denied")
        || text.contains("permission denied")
        || text.contains("must be root")
    {
        return ServiceControlError::AccessDenied;
    }
    if text.contains("not found") || text.contains("no such file or directory") {
        return ServiceControlError::NotInstalled;
    }
    ServiceControlError::Mechanism {
        detail: format!(
            "`{}` exited with {}: {}",
            argv.join(" "),
            outcome.exit_code,
            first_line(&outcome.stderr).unwrap_or("no output")
        ),
    }
}

fn first_line(text: &str) -> Option<&str> {
    text.lines().map(str::trim).find(|l| !l.is_empty())
}

/// Turn a filesystem failure into the port's error taxonomy. Writing under
/// `/etc` without root is the overwhelmingly common case and has its own code
/// so the console can say "open a root shell" instead of printing errno.
fn classify_io_failure(err: &io::Error, what: &str) -> ServiceControlError {
    match err.kind() {
        io::ErrorKind::PermissionDenied => ServiceControlError::AccessDenied,
        _ => ServiceControlError::Mechanism {
            detail: format!("{what}: {err}"),
        },
    }
}

// ── The port ─────────────────────────────────────────────────────────────────

/// systemd-backed [`ServiceControlPort`].
pub struct LinuxServiceControl {
    ops: Box<dyn SystemdOps>,
}

impl LinuxServiceControl {
    /// The production instance: real filesystem, real `systemctl`.
    pub fn new() -> Self {
        Self {
            ops: Box::new(FsOps),
        }
    }

    /// Build against a substitute for the host — used by this module's tests.
    pub fn with_ops(ops: Box<dyn SystemdOps>) -> Self {
        Self { ops }
    }

    /// Run one command, mapping both "could not spawn" and "exited non-zero"
    /// onto the port's errors.
    fn run_checked(&self, argv: &[String]) -> Result<CommandOutcome, ServiceControlError> {
        let outcome = self
            .ops
            .run(argv)
            .map_err(|e| classify_io_failure(&e, &format!("running `{}`", argv.join(" "))))?;
        if outcome.succeeded() {
            Ok(outcome)
        } else {
            Err(classify_command_failure(&outcome, argv))
        }
    }

    fn execute_install_plan(&self, plan: &SystemdInstallPlan) -> Result<(), ServiceControlError> {
        // The whole install footprint goes on disk before systemd is told about
        // it: unit, drop-in, alias, then daemon-reload / enable.
        self.ops
            .write_file(&plan.unit_path, &plan.unit_contents, 0o644)
            .map_err(|e| classify_io_failure(&e, "writing the unit file"))?;
        for file in &plan.additional_files {
            self.ops
                .write_file(&file.path, &file.contents, file.mode)
                .map_err(|e| classify_io_failure(&e, "writing an install file"))?;
        }
        for link in &plan.symlinks {
            self.ops
                .symlink(&link.target, &link.link_path)
                .map_err(|e| classify_io_failure(&e, "creating the alias symlink"))?;
        }
        for cmd in &plan.post_write_commands {
            self.run_checked(cmd)?;
        }
        Ok(())
    }

    fn execute_uninstall_plan(
        &self,
        plan: &SystemdUninstallPlan,
    ) -> Result<(), ServiceControlError> {
        for cmd in &plan.pre_remove_commands {
            self.run_checked(cmd)?;
        }
        self.ops
            .remove_file(&plan.unit_path)
            .map_err(|e| classify_io_failure(&e, "removing the unit file"))?;
        for path in &plan.additional_files_to_remove {
            self.ops
                .remove_file(path)
                .map_err(|e| classify_io_failure(&e, "removing an install file"))?;
        }
        for cmd in &plan.post_remove_commands {
            self.run_checked(cmd)?;
        }
        Ok(())
    }

    /// Is the unit active right now? `is-active` answers with its exit code, so
    /// a non-zero one is the answer "no", not a failure.
    fn is_active(&self) -> Result<bool, ServiceControlError> {
        let argv = systemctl(&["is-active", "--quiet", SYSTEMD_UNIT_NAME]);
        let outcome = self
            .ops
            .run(&argv)
            .map_err(|e| classify_io_failure(&e, "querying the unit state"))?;
        Ok(outcome.succeeded())
    }

    /// Poll until the unit reaches `want_active`, or the budget runs out.
    fn await_state(
        &self,
        want_active: bool,
        timeout: Duration,
        operation: &'static str,
    ) -> Result<(), ServiceControlError> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.is_active()? == want_active {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(ServiceControlError::Timeout {
                    operation,
                    seconds: timeout.as_secs(),
                });
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }
}

impl Default for LinuxServiceControl {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a `systemctl` argv. One place, so no call site can misspell it.
fn systemctl(args: &[&str]) -> Vec<String> {
    std::iter::once("systemctl".to_string())
        .chain(args.iter().map(|a| a.to_string()))
        .collect()
}

/// Translate an install spec into the unit configuration systemd renders from.
fn unit_config(spec: &ServiceInstallSpec) -> SystemdServiceConfig {
    let mut cfg = SystemdServiceConfig::for_binary(spec.binary_path.clone());
    cfg.watchdog_sec = Some(WATCHDOG_SEC);
    // systemd expresses the restart delay in whole seconds; a sub-second policy
    // rounds up rather than down to zero, which would be a restart storm.
    cfg.restart_sec = spec.recovery.first_restart_delay_ms.div_ceil(1_000).max(1);
    cfg.start_limit_burst = spec.recovery.max_auto_restarts;
    cfg.start_limit_interval_sec = spec.recovery.reset_period_secs;
    cfg
}

/// The neutral start mode, in systemd's terms.
fn activation_for(start_mode: ServiceStartMode) -> UnitActivation {
    match start_mode {
        ServiceStartMode::WithWindows => UnitActivation::EnableNow,
        ServiceStartMode::OnAppLaunch => UnitActivation::LeaveDisabled,
    }
}

impl ServiceControlPort for LinuxServiceControl {
    fn install(
        &self,
        spec: &ServiceInstallSpec,
    ) -> Result<ServiceInstallReport, ServiceControlError> {
        if spec.account_name.is_some() {
            // The unit deliberately runs as root: the enforcement backend needs
            // raw nftables and rtnetlink. Silently ignoring a requested account
            // would install a service with privileges the caller did not ask
            // for, so this refuses instead.
            return Err(ServiceControlError::Unsupported {
                operation: "installing the service under a specific account",
            });
        }
        let plan = plan_install(&unit_config(spec), activation_for(spec.start_mode));
        self.execute_install_plan(&plan)?;
        Ok(ServiceInstallReport {
            // systemd provisions StateDirectory / LogsDirectory itself, at the
            // mode the unit declares, when the service first starts — so this
            // install creates no directories and tightens no permissions of its
            // own. Reporting `None` says exactly that, rather than claiming
            // credit for what the unit file will do later.
            data_dirs_created: Vec::new(),
            recovery_configured: true,
            acl_applied: None,
        })
    }

    fn uninstall(
        &self,
        spec: &ServiceUninstallSpec,
    ) -> Result<ServiceUninstallReport, ServiceControlError> {
        // The registered ExecStart is the only reliable source of the daemon
        // path, and the alias symlink can only be swept up if it is known.
        let Some(registration) = self.query()? else {
            return Err(ServiceControlError::NotInstalled);
        };
        let binary_path = registration.binary_path;
        let plan = plan_uninstall(binary_path.as_deref());
        self.execute_uninstall_plan(&plan)?;

        if !spec.remove_service_owned_data {
            return Ok(ServiceUninstallReport {
                data_removed: false,
            });
        }
        // Only the two directories the unit itself provisions. User rule files
        // live outside them and are never touched.
        for dir in [state_dir(), log_dir()] {
            self.ops
                .remove_dir_all(&dir)
                .map_err(|e| classify_io_failure(&e, "removing the service data directory"))?;
        }
        Ok(ServiceUninstallReport { data_removed: true })
    }

    fn start(&self, timeout: Duration) -> Result<(), ServiceControlError> {
        if self.query()?.is_none() {
            return Err(ServiceControlError::NotInstalled);
        }
        // `--no-block` returns as soon as the job is queued, so the wait below
        // is ours to bound rather than systemd's.
        self.run_checked(&systemctl(&["start", "--no-block", SYSTEMD_UNIT_NAME]))?;
        self.await_state(true, timeout, "start")
    }

    fn stop(&self, timeout: Duration) -> Result<(), ServiceControlError> {
        if self.query()?.is_none() {
            return Err(ServiceControlError::NotInstalled);
        }
        self.run_checked(&systemctl(&["stop", "--no-block", SYSTEMD_UNIT_NAME]))?;
        self.await_state(false, timeout, "stop")
    }

    fn query(&self) -> Result<Option<ServiceStatusReport>, ServiceControlError> {
        let argv = systemctl(&[
            "show",
            SYSTEMD_UNIT_NAME,
            &format!("--property={SHOW_PROPERTIES}"),
        ]);
        let outcome = self
            .ops
            .run(&argv)
            .map_err(|e| classify_io_failure(&e, "querying the service registration"))?;
        if !outcome.succeeded() {
            return Err(classify_command_failure(&outcome, &argv));
        }
        Ok(parse_show_output(&outcome.stdout))
    }
}

#[cfg(test)]
mod tests {
    // Test assertions panic on infallible fixtures by design.
    #![allow(clippy::expect_used)]
    use super::*;
    use nrr_platform_api::service_control::RecoveryPolicy;
    use std::cell::RefCell;

    const DAEMON: &str = "/usr/lib/netrulerouter/nrr-serviced";

    /// The recorded side effects, shared between the port (which owns its ops)
    /// and the test (which reads them).
    type Journal = std::rc::Rc<RefCell<Vec<String>>>;

    /// A stand-in host: records every side effect in order and answers commands
    /// from a scripted table.
    struct Fake {
        ops: Journal,
        /// Answer for any command whose joined argv contains the key. First
        /// match wins, so a specific entry can precede a general one.
        answers: Vec<(&'static str, CommandOutcome)>,
        default_answer: CommandOutcome,
    }

    fn ok(stdout: &str) -> CommandOutcome {
        CommandOutcome {
            exit_code: 0,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    fn failed(code: i32, stderr: &str) -> CommandOutcome {
        CommandOutcome {
            exit_code: code,
            stdout: String::new(),
            stderr: stderr.to_string(),
        }
    }

    /// What `systemctl show` prints for an installed, enabled, running unit.
    fn show_running() -> String {
        format!(
            "LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n\
             ExecStart={{ path={DAEMON} ; argv[]={DAEMON} run ; ignore_errors=no }}\n"
        )
    }

    fn show_absent() -> String {
        "LoadState=not-found\nActiveState=inactive\nUnitFileState=\nExecStart=\n".to_string()
    }

    /// Build a port over a recording host. Returns the port and the journal the
    /// assertions read.
    fn port_over(answers: Vec<(&'static str, CommandOutcome)>) -> (LinuxServiceControl, Journal) {
        let journal: Journal = std::rc::Rc::new(RefCell::new(Vec::new()));
        let fake = Fake {
            ops: journal.clone(),
            answers,
            default_answer: ok(""),
        };
        (LinuxServiceControl::with_ops(Box::new(fake)), journal)
    }

    /// Everything the host was asked to do, in order.
    fn recorded(journal: &Journal) -> Vec<String> {
        journal.borrow().clone()
    }

    impl SystemdOps for Fake {
        fn write_file(&self, path: &Path, _contents: &str, mode: u32) -> io::Result<()> {
            self.ops
                .borrow_mut()
                .push(format!("write {} {:o}", path.display(), mode));
            Ok(())
        }
        fn remove_file(&self, path: &Path) -> io::Result<()> {
            self.ops
                .borrow_mut()
                .push(format!("remove {}", path.display()));
            Ok(())
        }
        fn remove_dir_all(&self, path: &Path) -> io::Result<()> {
            self.ops
                .borrow_mut()
                .push(format!("remove-tree {}", path.display()));
            Ok(())
        }
        fn symlink(&self, target: &Path, link: &Path) -> io::Result<()> {
            self.ops
                .borrow_mut()
                .push(format!("link {} -> {}", link.display(), target.display()));
            Ok(())
        }
        fn run(&self, argv: &[String]) -> io::Result<CommandOutcome> {
            let joined = argv.join(" ");
            self.ops.borrow_mut().push(format!("run {joined}"));
            for (needle, outcome) in &self.answers {
                if joined.contains(needle) {
                    return Ok(outcome.clone());
                }
            }
            Ok(self.default_answer.clone())
        }
    }

    fn install_spec(start_mode: ServiceStartMode) -> ServiceInstallSpec {
        ServiceInstallSpec {
            binary_path: PathBuf::from(DAEMON),
            recovery: RecoveryPolicy::production(),
            start_mode,
            account_name: None,
            create_data_dirs: true,
        }
    }

    // ── parsing systemd's answers ────────────────────────────────────────────

    #[test]
    fn an_unknown_unit_is_not_installed_rather_than_an_error() {
        // systemd answers for units it does not have; the answer is LoadState.
        assert_eq!(parse_show_output(&show_absent()), None);
    }

    #[test]
    fn a_running_enabled_unit_reports_state_mode_and_binary() {
        let report = parse_show_output(&show_running()).expect("installed");
        assert_eq!(report.run_state, ServiceRunState::Running);
        assert_eq!(report.start_mode, Some(ServiceStartMode::WithWindows));
        assert_eq!(report.binary_path, Some(PathBuf::from(DAEMON)));
    }

    #[test]
    fn a_disabled_unit_reports_start_on_demand() {
        // Installed but not wired into the boot target: the neutral vocabulary
        // for that is "starts when the application asks".
        let text = "LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\n";
        let report = parse_show_output(text).expect("installed");
        assert_eq!(report.run_state, ServiceRunState::Stopped);
        assert_eq!(report.start_mode, Some(ServiceStartMode::OnAppLaunch));
        assert_eq!(report.binary_path, None);
    }

    #[test]
    fn transitional_states_are_not_reported_as_stopped() {
        for (active_state, expected) in [
            ("activating", ServiceRunState::StartPending),
            ("deactivating", ServiceRunState::StopPending),
            ("failed", ServiceRunState::Stopped),
            ("reloading", ServiceRunState::Other),
        ] {
            let text = format!("LoadState=loaded\nActiveState={active_state}\n");
            assert_eq!(
                parse_show_output(&text).expect("installed").run_state,
                expected,
                "ActiveState={active_state}"
            );
        }
    }

    #[test]
    fn the_binary_comes_from_the_exec_start_record_not_the_whole_line() {
        // systemd renders ExecStart as a structured record; taking the whole
        // value would hand the caller a path with `; argv[]=…` glued to it.
        let path = exec_start_binary(&format!(
            "{{ path={DAEMON} ; argv[]={DAEMON} run ; ignore_errors=no }}"
        ));
        assert_eq!(path, Some(PathBuf::from(DAEMON)));
        assert_eq!(exec_start_binary(""), None);
    }

    #[test]
    fn a_privilege_failure_is_told_apart_from_a_broken_one() {
        let argv = systemctl(&["enable", "--now", SYSTEMD_UNIT_NAME]);
        // polkit with no agent attached — the usual way this fails over SSH.
        assert_eq!(
            classify_command_failure(&failed(1, "Interactive authentication required."), &argv),
            ServiceControlError::AccessDenied
        );
        assert_eq!(
            classify_command_failure(&failed(1, "Permission denied"), &argv),
            ServiceControlError::AccessDenied
        );
        assert_eq!(
            classify_command_failure(&failed(5, "Unit netrulerouter.service not found."), &argv),
            ServiceControlError::NotInstalled
        );
        // Anything else keeps the manager's own words, plus the command that
        // produced them.
        let other = classify_command_failure(&failed(1, "Job failed. See journalctl"), &argv);
        match other {
            ServiceControlError::Mechanism { detail } => {
                assert!(detail.contains("systemctl enable"), "{detail}");
                assert!(detail.contains("Job failed"), "{detail}");
            }
            other => panic!("unexpected classification: {other:?}"),
        }
    }

    // ── the port, end to end against a recorded host ─────────────────────────

    #[test]
    fn install_puts_every_file_in_place_before_telling_systemd() {
        let (port, journal) = port_over(vec![]);
        let report = port
            .install(&install_spec(ServiceStartMode::WithWindows))
            .expect("install");

        assert!(report.recovery_configured);
        // systemd provisions the state dirs itself, so this install claims none
        // and tightened no permissions of its own.
        assert!(report.data_dirs_created.is_empty());
        assert_eq!(report.acl_applied, None);

        assert_eq!(
            recorded(&journal),
            vec![
                "write /etc/systemd/system/netrulerouter.service 644".to_string(),
                "write /etc/logrotate.d/netrulerouter 644".to_string(),
                "link /usr/lib/netrulerouter/nrr-service -> /usr/lib/netrulerouter/nrr-serviced"
                    .to_string(),
                "run systemctl daemon-reload".to_string(),
                "run systemctl enable --now netrulerouter.service".to_string(),
            ]
        );
    }

    #[test]
    fn an_on_demand_install_does_not_enable_the_unit() {
        let (port, journal) = port_over(vec![]);
        port.install(&install_spec(ServiceStartMode::OnAppLaunch))
            .expect("install");
        let ops = recorded(&journal);
        assert!(ops.iter().any(|o| o.contains("daemon-reload")), "{ops:?}");
        assert!(
            !ops.iter().any(|o| o.contains("enable")),
            "on-demand must not wire the unit into the boot target: {ops:?}"
        );
    }

    #[test]
    fn installing_under_an_account_is_refused_rather_than_silently_ignored() {
        let (port, journal) = port_over(vec![]);
        let mut spec = install_spec(ServiceStartMode::WithWindows);
        spec.account_name = Some("nrr".to_string());
        assert!(matches!(
            port.install(&spec),
            Err(ServiceControlError::Unsupported { .. })
        ));
        // A refused install leaves no debris.
        assert!(recorded(&journal).is_empty());
    }

    #[test]
    fn the_recovery_policy_reaches_the_unit_file() {
        let cfg = unit_config(&install_spec(ServiceStartMode::WithWindows));
        let policy = RecoveryPolicy::production();
        assert_eq!(cfg.start_limit_burst, policy.max_auto_restarts);
        assert_eq!(cfg.start_limit_interval_sec, policy.reset_period_secs);
        assert_eq!(cfg.restart_sec, policy.first_restart_delay_ms / 1_000);
    }

    #[test]
    fn a_sub_second_restart_delay_never_rounds_down_to_zero() {
        // RestartSec=0 is a restart storm, which is the opposite of a recovery
        // policy.
        let mut spec = install_spec(ServiceStartMode::WithWindows);
        spec.recovery.first_restart_delay_ms = 200;
        assert_eq!(unit_config(&spec).restart_sec, 1);
    }

    #[test]
    fn uninstall_removes_the_footprint_and_keeps_data_by_default() {
        let (port, journal) = port_over(vec![("show", ok(&show_running()))]);
        let report = port
            .uninstall(&ServiceUninstallSpec::keep_data())
            .expect("uninstall");
        assert!(!report.data_removed);
        let ops = recorded(&journal);
        assert!(
            !ops.iter().any(|o| o.starts_with("remove-tree")),
            "keeping data must not delete a directory: {ops:?}"
        );
        // Disable while the unit file still exists, then remove the footprint,
        // then reload — systemd must never hold a reference to a unit whose
        // file has vanished. The alias is swept up too, which is only possible
        // because the registered ExecStart told us where the daemon lives.
        assert_eq!(
            ops.into_iter()
                .filter(|o| !o.contains("show"))
                .collect::<Vec<_>>(),
            vec![
                "run systemctl disable --now netrulerouter.service".to_string(),
                "remove /etc/systemd/system/netrulerouter.service".to_string(),
                "remove /etc/logrotate.d/netrulerouter".to_string(),
                "remove /usr/lib/netrulerouter/nrr-service".to_string(),
                "run systemctl daemon-reload".to_string(),
            ]
        );
    }

    #[test]
    fn a_failing_command_stops_the_walk_instead_of_carrying_on() {
        // `enable` must not run after `daemon-reload` failed: systemd would be
        // enabling a unit it has not re-read.
        let (port, journal) = port_over(vec![("daemon-reload", failed(1, "Failed to reload"))]);
        assert!(port
            .install(&install_spec(ServiceStartMode::WithWindows))
            .is_err());
        let ops = recorded(&journal);
        assert!(
            !ops.iter().any(|o| o.contains("enable")),
            "the walk continued past a failure: {ops:?}"
        );
    }

    #[test]
    fn a_repeat_install_replaces_the_alias_instead_of_failing() {
        // `symlink(2)` refuses an existing path, so the real executor unlinks
        // first. Exercised against the real filesystem because that ordering is
        // the whole substance of the operation.
        let dir = std::env::temp_dir().join(format!("nrr-alias-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let target = dir.join("nrr-serviced");
        std::fs::write(&target, b"#!/bin/true\n").expect("write target");
        let link = dir.join("nrr-service");

        let fs = FsOps;
        fs.symlink(&target, &link).expect("first link");
        fs.symlink(&target, &link)
            .expect("second link must not fail");

        assert_eq!(
            std::fs::read_link(&link).expect("link resolves"),
            target,
            "the alias must point at the daemon that was just installed"
        );
        // Removing the link must not touch what it points at.
        fs.remove_file(&link).expect("unlink");
        assert!(!link.exists());
        assert!(target.exists(), "the daemon binary must survive unlinking");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_purging_uninstall_deletes_only_the_directories_the_unit_provisions() {
        let (port, journal) = port_over(vec![("show", ok(&show_running()))]);
        let report = port
            .uninstall(&ServiceUninstallSpec::purge_data())
            .expect("uninstall");
        assert!(report.data_removed);
        let trees: Vec<String> = recorded(&journal)
            .into_iter()
            .filter(|o| o.starts_with("remove-tree"))
            .collect();
        assert_eq!(
            trees,
            vec![
                "remove-tree /var/lib/netrulerouter".to_string(),
                "remove-tree /var/log/netrulerouter".to_string(),
            ]
        );
    }

    #[test]
    fn start_refuses_before_touching_systemd_when_nothing_is_installed() {
        let (port, journal) = port_over(vec![("show", ok(&show_absent()))]);
        assert_eq!(
            port.start(Duration::from_secs(1)),
            Err(ServiceControlError::NotInstalled)
        );
        assert!(
            !recorded(&journal).iter().any(|o| o.contains("start")),
            "no start job should be queued for a unit that does not exist"
        );
    }

    #[test]
    fn start_waits_for_the_unit_to_become_active() {
        let (port, journal) = port_over(vec![("show", ok(&show_running())), ("is-active", ok(""))]);
        port.start(Duration::from_secs(5)).expect("start");
        let ops = recorded(&journal);
        assert!(ops
            .iter()
            .any(|o| o == "run systemctl start --no-block netrulerouter.service"));
        assert!(ops.iter().any(|o| o.contains("is-active")));
    }

    #[test]
    fn stop_is_satisfied_by_a_unit_that_is_already_inactive() {
        // `is-active` exits non-zero for an inactive unit — that is the answer,
        // not a failure, and stopping something already stopped must succeed.
        let (port, _journal) = port_over(vec![
            ("show", ok(&show_running())),
            ("is-active", failed(3, "inactive")),
        ]);
        port.stop(Duration::from_secs(5)).expect("stop");
    }

    #[test]
    fn a_start_that_never_becomes_active_times_out_with_its_own_error() {
        let (port, _journal) = port_over(vec![
            ("show", ok(&show_running())),
            ("is-active", failed(3, "inactive")),
        ]);
        assert_eq!(
            port.start(Duration::from_millis(0)),
            Err(ServiceControlError::Timeout {
                operation: "start",
                seconds: 0
            })
        );
    }

    #[test]
    fn query_reports_the_registration_without_starting_anything() {
        let (port, journal) = port_over(vec![("show", ok(&show_running()))]);
        let report = port.query().expect("query").expect("installed");
        assert_eq!(report.run_state, ServiceRunState::Running);
        assert_eq!(recorded(&journal).len(), 1, "query must be one command");
    }

    #[test]
    fn query_without_privilege_reports_access_denied() {
        let (port, _journal) = port_over(vec![(
            "show",
            failed(1, "Interactive authentication required."),
        )]);
        assert_eq!(port.query(), Err(ServiceControlError::AccessDenied));
    }
}
