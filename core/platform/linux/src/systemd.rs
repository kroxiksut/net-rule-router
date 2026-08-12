//! Linux systemd service mechanism (`Type=notify` unit +
//! `sd_notify` readiness protocol). The Linux analog of the Windows SCM
//! entrypoint (`core/services/windows-service`, `scm.rs`).
//!
//! Two independent, pure-core mechanisms live here; neither takes an external
//! crate (plain `std` + the Linux `AF_UNIX` datagram syscall):
//!
//! 1. **Unit-file rendering** ([`render_service_unit`]) — produces the
//!    `netrulerouter.service` unit text. `Type=notify` so systemd waits for the
//!    daemon's own readiness signal (the Linux equivalent of reporting
//!    `SERVICE_RUNNING` to SCM only after bootstrap completes). The unit's
//!    `RuntimeDirectory=netrulerouter` / `StateDirectory=netrulerouter`
//!    directives create the `0700` directories the daemon needs: the IPC
//!    socket under `/run/netrulerouter/` and the DB-MAC key under
//!    `/var/lib/netrulerouter/`.
//!
//! 2. **`sd_notify`** — the daemon → manager readiness datagram. systemd hands
//!    the daemon an `AF_UNIX` datagram address in `$NOTIFY_SOCKET`; the daemon
//!    sends newline-separated `KEY=value` assignments (`READY=1`, `STATUS=…`,
//!    `WATCHDOG=1`, `STOPPING=1`, …). Message construction
//!    ([`render_notify_message`]), address parsing ([`parse_notify_socket`],
//!    handling both pathname and `@`-abstract-namespace sockets), the datagram
//!    send ([`send_notify_to`], tested against a local receiver), and the
//!    watchdog-interval derivation ([`watchdog_interval`]) are all pure /
//!    unit-tested on WSL2. Only [`notify`]'s single `$NOTIFY_SOCKET` env read is
//!    left uncovered — the same discipline applied to `elevation`'s
//!    `run_pkexec`, its one un-unit-testable spawn.
//!
//! `#[cfg(target_os = "linux")]`: the abstract-namespace address form is a
//! Linux-specific extension (`std::os::linux::net`), so the module is compiled
//! and tested on Linux (WSL2) only, mirroring `key_store`.

#![cfg(target_os = "linux")]

use std::io;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::path::{Path, PathBuf};
use std::time::Duration;

// ── Unit-file rendering ──────────────────────────────────────────────────────

/// Inputs for rendering the `netrulerouter.service` systemd unit. Mirrors the
/// Windows install metadata (`SERVICE_DISPLAY_NAME` / `SERVICE_DESCRIPTION` +
/// the service binary path) that `windows-service` hands SCM.
#[derive(Debug, Clone)]
pub struct SystemdServiceConfig {
    /// One-line `Description=` shown by `systemctl status`.
    pub description: String,
    /// Absolute path to the daemon binary
    /// (e.g. `/usr/lib/netrulerouter/nrr-serviced`). The `ExecStart=` line and
    /// the alias symlink are both derived from it, so the unit can never point
    /// at one file while the alias points at another.
    pub binary_path: PathBuf,
    /// When set, emit `WatchdogSec=<n>` so systemd expects a periodic
    /// `WATCHDOG=1` ping and restarts the daemon if it goes silent. `None`
    /// disables the hardware-watchdog contract.
    pub watchdog_sec: Option<u32>,
    /// Seconds systemd waits before restarting a crashed daemon (`RestartSec=`).
    pub restart_sec: u32,
    /// How many restarts within [`Self::start_limit_interval_sec`] systemd
    /// attempts before giving up and leaving the unit failed
    /// (`StartLimitBurst=`). The point is the same as the Windows failure
    /// actions': recover from a crash, but never spin forever on a daemon that
    /// cannot start.
    pub start_limit_burst: u8,
    /// The window the restart counter is measured over
    /// (`StartLimitIntervalSec=`).
    pub start_limit_interval_sec: u32,
}

impl SystemdServiceConfig {
    /// Configuration for a daemon at `binary_path`, with the product's own
    /// name as the description and recovery values matching the Windows
    /// production policy. Callers adjust individual fields afterwards rather
    /// than spelling every one of them.
    pub fn for_binary(binary_path: PathBuf) -> Self {
        Self {
            description: nrr_shared::product_identity::SERVICE_DISPLAY_NAME.to_string(),
            binary_path,
            watchdog_sec: None,
            restart_sec: 5,
            start_limit_burst: 2,
            start_limit_interval_sec: 86_400,
        }
    }
}

/// Whether the installed unit is wired into the boot target.
///
/// The neutral start-mode vocabulary ("start with the OS" vs "start when the
/// application asks") maps onto exactly this: an enabled unit comes up on boot,
/// a merely installed one waits to be started. Kept as its own type so this
/// module stays free of the port's vocabulary — it renders systemd, it does not
/// know what a `ServiceStartMode` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitActivation {
    /// `systemctl enable --now`: start it and bring it up on every boot.
    EnableNow,
    /// Install the unit but leave it disabled and stopped; something else will
    /// start it on demand.
    LeaveDisabled,
}

/// The argument the unit passes to the daemon. Declared once: the same word has
/// to appear in `ExecStart=` and in the daemon's own verb table, and a typo in
/// either is a unit that starts nothing.
const DAEMON_RUN_VERB: &str = "run";

/// The `RuntimeDirectory=` / `StateDirectory=` leaf. Kept next to the paths in
/// the IPC address (`/run/netrulerouter/…`) and the secrets store
/// (`/var/lib/netrulerouter/…`) so all three agree on one directory name.
const RUNTIME_STATE_DIR: &str = "netrulerouter";

/// Render the full `netrulerouter.service` unit text.
///
/// The unit runs the daemon as root (no `User=`): the MVP enforcement backend
/// needs raw `nftables` + `rtnetlink`, and the design fixes the privileged
/// process as a root systemd service (elevation is a polkit/IPC concern for the
/// GUI, not this unit). `Restart=on-failure` gives crash recovery analogous to
/// the Windows SCM failure actions.
pub fn render_service_unit(cfg: &SystemdServiceConfig) -> String {
    let mut s = String::with_capacity(512);
    s.push_str("[Unit]\n");
    s.push_str(&format!("Description={}\n", cfg.description));
    // Routing/enforcement only makes sense once the network stack is up.
    s.push_str("After=network-online.target\n");
    s.push_str("Wants=network-online.target\n");
    // Crash-recovery bounds live in [Unit], not [Service]: they cap how often
    // the `Restart=` below is allowed to fire, so a daemon that cannot start is
    // left failed for an operator instead of restarting forever.
    s.push_str(&format!(
        "StartLimitIntervalSec={}\n",
        cfg.start_limit_interval_sec
    ));
    s.push_str(&format!("StartLimitBurst={}\n", cfg.start_limit_burst));
    s.push('\n');

    s.push_str("[Service]\n");
    // Type=notify: systemd holds the unit "activating" until the daemon sends
    // READY=1 (see `notify_ready`), matching the Windows "report Running only
    // after bootstrap" contract.
    s.push_str("Type=notify\n");
    s.push_str(&format!(
        "ExecStart={} {DAEMON_RUN_VERB}\n",
        cfg.binary_path.display()
    ));
    s.push_str("Restart=on-failure\n");
    s.push_str(&format!("RestartSec={}\n", cfg.restart_sec));
    if let Some(sec) = cfg.watchdog_sec {
        s.push_str(&format!("WatchdogSec={sec}\n"));
    }
    // Create /run/netrulerouter and /var/lib/netrulerouter at 0700, owned by the
    // service. These are the canonical IPC-socket and DB-MAC-key homes;
    // systemd manages their lifecycle so the daemon never
    // has to mkdir/chmod them itself.
    s.push_str(&format!("RuntimeDirectory={RUNTIME_STATE_DIR}\n"));
    s.push_str("RuntimeDirectoryMode=0700\n");
    s.push_str(&format!("StateDirectory={RUNTIME_STATE_DIR}\n"));
    s.push_str("StateDirectoryMode=0700\n");
    // Create /var/log/netrulerouter at 0700, owned by the service. This is the
    // operational-NDJSON home that nrr-storage's Linux `logs_dir` targets (split
    // out from StateDirectory per FHS: /var/log for logs, /var/lib for state).
    // systemd owning it means the daemon never has to mkdir/chmod it, and the
    // logrotate backstop drop-in (see `logrotate.rs`) governs only this path.
    s.push_str(&format!("LogsDirectory={RUNTIME_STATE_DIR}\n"));
    s.push_str("LogsDirectoryMode=0700\n");
    // Minimal hardening that does not interfere with net-admin duties.
    s.push_str("NoNewPrivileges=yes\n");
    s.push_str("ProtectHome=yes\n");
    s.push('\n');

    s.push_str("[Install]\n");
    s.push_str("WantedBy=multi-user.target\n");
    s
}

// ── install / uninstall plan ─────────────────────────────────────────────────

/// The unit file name systemd looks for under [`SYSTEMD_UNIT_DIR`]. The Linux
/// analog of the Windows `SERVICE_NAME` registration key — both are derived
/// from the same product identity, so renaming the product cannot rename one
/// without the other.
pub const SYSTEMD_UNIT_NAME: &str = nrr_shared::product_identity::SYSTEMD_UNIT_NAME;

/// The system-wide systemd unit directory `install` writes into. Root-owned, so
/// writing here requires privilege — the daemon's `install` verb runs elevated,
/// mirroring the Windows `install` verb's admin requirement.
pub const SYSTEMD_UNIT_DIR: &str = "/etc/systemd/system";

/// A computed, side-effect-free plan for `linux-service install` — the Linux
/// analog of the Windows `scm.rs::install_service` sequence (register unit →
/// enable → start). Separating the plan (what to write / run) from its execution
/// keeps the decision testable without a systemd host or root: the unit text,
/// the target path, and the exact `systemctl` argv lines are all asserted on
/// WSL2, while the thin executor that writes the file and spawns the commands is
/// the only part that needs a real host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdInstallPlan {
    /// Absolute path to write the rendered unit to
    /// (`/etc/systemd/system/netrulerouter.service`).
    pub unit_path: PathBuf,
    /// The full unit-file contents to write there ([`render_service_unit`]).
    pub unit_contents: String,
    /// Non-unit files the installer must also write, in order — currently the
    /// logrotate backstop drop-in (`/etc/logrotate.d/netrulerouter`). Kept as a
    /// list so the daemon's `install` verb writes the whole install footprint
    /// from a single computed plan, while each file's CONTENTS are still
    /// rendered (and tested) by its own module.
    pub additional_files: Vec<InstallFile>,
    /// Symlinks the installer must create, in order — currently the role alias
    /// (`nrr-service` → `nrr-serviced`) next to the daemon binary. See
    /// [`alias_link`] for why it lives there and not in a `PATH` directory.
    pub symlinks: Vec<SymlinkSpec>,
    /// Commands to run AFTER the unit file is in place, in order, each as an
    /// argv vector (no shell — the same no-quoting discipline as
    /// [`crate::elevation::pkexec_argv`]). `daemon-reload` makes systemd read
    /// the new unit; `enable --now` starts it and wires it into
    /// `multi-user.target` so it comes up on boot.
    pub post_write_commands: Vec<Vec<String>>,
}

/// A symlink the installer creates: `link_path` will point at `target`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymlinkSpec {
    /// Where the link itself is created.
    pub link_path: PathBuf,
    /// What the link resolves to.
    pub target: PathBuf,
}

/// A single non-unit file the installer writes (path + contents + mode). The
/// mode distinguishes the `0700`-territory systemd manages itself from the
/// world-readable configs (logrotate drop-in) that live under `/etc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallFile {
    /// Absolute destination path.
    pub path: PathBuf,
    /// Full file contents.
    pub contents: String,
    /// Unix mode bits (octal), e.g. `0o644` for an `/etc` config.
    pub mode: u32,
}

/// Where the role alias (`nrr-service`) is installed for a daemon at
/// `binary_path`: **next to the daemon binary**, not in a `PATH` directory.
///
/// The alias exists so one name works on every OS — the Windows service binary
/// is `nrr-service.exe` and the Unix daemon is `nrr-serviced`, which would
/// otherwise force cross-platform scripts to branch. Making a binary reachable
/// by bare name is a separate decision (it changes the environment of every
/// future shell), so install does not take it: on Windows the console is added
/// to `PATH` only by an explicit user action, and this mirrors that.
/// Directories under `/usr/bin` also belong to the package manager, not to us.
///
/// Returns `None` when there is nothing to link: the daemon is already named
/// like the alias (a self-link), or its path is not absolute. A relative path
/// would put the link wherever the installing process happened to be running
/// from, which is never what the operator meant — and `current_exe()`, the only
/// production source of this path, is always absolute.
pub fn alias_link(binary_path: &Path) -> Option<SymlinkSpec> {
    let alias = nrr_shared::product_identity::BinaryRole::Service.unix_alias()?;
    if !binary_path.is_absolute() {
        return None;
    }
    let parent = binary_path.parent()?;
    if binary_path.file_name()? == std::ffi::OsStr::new(alias) {
        return None;
    }
    Some(SymlinkSpec {
        link_path: parent.join(alias),
        target: binary_path.to_path_buf(),
    })
}

/// Compute the [`SystemdInstallPlan`] for a service configuration. Pure — no
/// filesystem or process side effects. Includes the logrotate backstop drop-in
/// (rendered by [`crate::logrotate`]) as an additional file so a single install
/// plan covers the unit AND the log-rotation safety net.
pub fn plan_install(cfg: &SystemdServiceConfig, activation: UnitActivation) -> SystemdInstallPlan {
    // `daemon-reload` always runs — systemd must read the unit that was just
    // written whether or not it is being started. Enabling is what the start
    // mode actually decides.
    let mut post_write_commands = vec![vec!["systemctl".to_string(), "daemon-reload".to_string()]];
    if activation == UnitActivation::EnableNow {
        post_write_commands.push(vec![
            "systemctl".to_string(),
            "enable".to_string(),
            "--now".to_string(),
            SYSTEMD_UNIT_NAME.to_string(),
        ]);
    }
    SystemdInstallPlan {
        unit_path: Path::new(SYSTEMD_UNIT_DIR).join(SYSTEMD_UNIT_NAME),
        unit_contents: render_service_unit(cfg),
        additional_files: vec![InstallFile {
            path: crate::logrotate::config_file(),
            contents: crate::logrotate::render_logrotate_config(),
            // /etc/logrotate.d configs are world-readable by convention.
            mode: 0o644,
        }],
        symlinks: alias_link(&cfg.binary_path).into_iter().collect(),
        post_write_commands,
    }
}

/// The service-owned state directory systemd provisions via `StateDirectory=`
/// (`/var/lib/netrulerouter`). Declared here, next to the directive that
/// creates it, so a purge cannot delete a directory the unit never made.
pub fn state_dir() -> PathBuf {
    PathBuf::from("/var/lib").join(RUNTIME_STATE_DIR)
}

/// The operational-log directory systemd provisions via `LogsDirectory=`
/// (`/var/log/netrulerouter`). Same reasoning as [`state_dir`].
pub fn log_dir() -> PathBuf {
    PathBuf::from("/var/log").join(RUNTIME_STATE_DIR)
}

/// A computed, side-effect-free plan for `linux-service uninstall` — the Linux
/// analog of `scm.rs::uninstall_service` (stop → disable → delete). The unit is
/// disabled and stopped BEFORE its file is removed, so systemd never holds a
/// reference to a unit whose file has vanished; the trailing `daemon-reload`
/// clears the removed unit from systemd's in-memory view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdUninstallPlan {
    /// Commands to run BEFORE removing the unit file, in order.
    pub pre_remove_commands: Vec<Vec<String>>,
    /// The unit file to remove once the pre-remove commands succeed.
    pub unit_path: PathBuf,
    /// Additional install-footprint files to remove (the logrotate drop-in).
    /// Removed alongside the unit so uninstall leaves no orphaned `/etc`
    /// configs behind.
    pub additional_files_to_remove: Vec<PathBuf>,
    /// Commands to run AFTER the unit file is removed.
    pub post_remove_commands: Vec<Vec<String>>,
}

/// Compute the [`SystemdUninstallPlan`]. Pure — no filesystem or process side
/// effects. Removes the logrotate drop-in [`plan_install`] wrote, mirroring the
/// install footprint exactly.
///
/// `binary_path` is the daemon this uninstall belongs to, and it is optional
/// because uninstall must still work when the binary cannot be located: a
/// leftover alias symlink is cosmetic, an un-removable service is not. When it
/// is known, the alias [`plan_install`] created is removed with the rest of the
/// footprint — a dangling link to a deleted binary is exactly the kind of debris
/// the next installer trips over.
pub fn plan_uninstall(binary_path: Option<&Path>) -> SystemdUninstallPlan {
    let mut files_to_remove = vec![crate::logrotate::config_file()];
    if let Some(alias) = binary_path.and_then(alias_link) {
        files_to_remove.push(alias.link_path);
    }
    SystemdUninstallPlan {
        pre_remove_commands: vec![vec![
            "systemctl".to_string(),
            "disable".to_string(),
            "--now".to_string(),
            SYSTEMD_UNIT_NAME.to_string(),
        ]],
        unit_path: Path::new(SYSTEMD_UNIT_DIR).join(SYSTEMD_UNIT_NAME),
        additional_files_to_remove: files_to_remove,
        post_remove_commands: vec![vec!["systemctl".to_string(), "daemon-reload".to_string()]],
    }
}

// ── sd_notify ────────────────────────────────────────────────────────────────

/// One `sd_notify` state assignment. Rendered as a single `KEY=value` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifyState {
    /// `READY=1` — bootstrap complete; systemd may consider the unit started.
    Ready,
    /// `RELOADING=1` — the daemon is reloading configuration.
    Reloading,
    /// `STOPPING=1` — the daemon has begun an orderly shutdown.
    Stopping,
    /// `STATUS=<text>` — free-form single-line status for `systemctl status`.
    Status(String),
    /// `WATCHDOG=1` — keep-alive ping for the `WatchdogSec` contract.
    Watchdog,
    /// `MAINPID=<pid>` — declare the main PID (used when the notifying process
    /// differs from the one systemd forked).
    MainPid(u32),
}

impl NotifyState {
    /// Render the `KEY=value` form. `Status` is validated by
    /// [`render_notify_message`] before this is called.
    fn render(&self) -> String {
        match self {
            NotifyState::Ready => "READY=1".to_string(),
            NotifyState::Reloading => "RELOADING=1".to_string(),
            NotifyState::Stopping => "STOPPING=1".to_string(),
            NotifyState::Status(text) => format!("STATUS={text}"),
            NotifyState::Watchdog => "WATCHDOG=1".to_string(),
            NotifyState::MainPid(pid) => format!("MAINPID={pid}"),
        }
    }
}

/// The parsed `$NOTIFY_SOCKET` address. systemd uses either a filesystem path
/// or a `@`-prefixed Linux abstract-namespace name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifyAddress {
    /// Pathname socket (e.g. `/run/systemd/notify`).
    Path(PathBuf),
    /// Abstract-namespace socket, name WITHOUT the leading `@`/NUL.
    Abstract(String),
}

/// Failures constructing or delivering an `sd_notify` message.
#[derive(Debug)]
pub enum NotifyError {
    /// A `STATUS=` payload contained a newline, which would forge extra
    /// assignments in the datagram.
    MalformedStatus,
    /// `$NOTIFY_SOCKET` was empty or used an unsupported address form (systemd
    /// only ever sets an absolute path or a `@`-abstract name).
    UnsupportedAddress(String),
    /// The underlying `AF_UNIX` datagram send failed.
    Io(io::Error),
}

impl std::fmt::Display for NotifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotifyError::MalformedStatus => {
                write!(f, "sd_notify STATUS payload must not contain a newline")
            }
            NotifyError::UnsupportedAddress(a) => {
                write!(f, "unsupported NOTIFY_SOCKET address: {a:?}")
            }
            NotifyError::Io(e) => write!(f, "sd_notify send failed: {e}"),
        }
    }
}

impl std::error::Error for NotifyError {}

impl From<io::Error> for NotifyError {
    fn from(e: io::Error) -> Self {
        NotifyError::Io(e)
    }
}

/// Serialise a set of states into the newline-separated datagram body systemd
/// expects. No trailing newline is required (systemd accepts either form).
/// Rejects a `Status` carrying a newline, which would otherwise smuggle
/// additional assignments onto the wire.
pub fn render_notify_message(states: &[NotifyState]) -> Result<Vec<u8>, NotifyError> {
    for st in states {
        if let NotifyState::Status(text) = st {
            if text.contains('\n') {
                return Err(NotifyError::MalformedStatus);
            }
        }
    }
    let body = states
        .iter()
        .map(NotifyState::render)
        .collect::<Vec<_>>()
        .join("\n");
    Ok(body.into_bytes())
}

/// Parse the `$NOTIFY_SOCKET` value systemd exports.
///
/// - absolute path (`/…`) → [`NotifyAddress::Path`]
/// - `@name` → [`NotifyAddress::Abstract`] (the `@` marks the abstract
///   namespace; the real address is a leading NUL then `name`)
/// - anything else (empty, relative) → [`NotifyError::UnsupportedAddress`]
pub fn parse_notify_socket(value: &str) -> Result<NotifyAddress, NotifyError> {
    if let Some(name) = value.strip_prefix('@') {
        return Ok(NotifyAddress::Abstract(name.to_string()));
    }
    if value.starts_with('/') {
        return Ok(NotifyAddress::Path(PathBuf::from(value)));
    }
    Err(NotifyError::UnsupportedAddress(value.to_string()))
}

/// Build the `std` socket address for a parsed [`NotifyAddress`].
fn to_socket_addr(addr: &NotifyAddress) -> io::Result<SocketAddr> {
    match addr {
        NotifyAddress::Path(p) => SocketAddr::from_pathname(p),
        NotifyAddress::Abstract(name) => SocketAddr::from_abstract_name(name.as_bytes()),
    }
}

/// Send an `sd_notify` datagram to an explicit address. Split out from
/// [`notify`] so tests can drive a real send against a locally-bound receiver
/// socket without systemd. An unbound autobind source socket is used — systemd
/// does not require the sender to have a well-known address.
pub fn send_notify_to(addr: &NotifyAddress, states: &[NotifyState]) -> Result<(), NotifyError> {
    let body = render_notify_message(states)?;
    let sock_addr = to_socket_addr(addr)?;
    let sock = UnixDatagram::unbound()?;
    sock.connect_addr(&sock_addr)?;
    sock.send(&body)?;
    Ok(())
}

/// Resolve the notify address from an explicit `$NOTIFY_SOCKET` value (or its
/// absence) and send. Returns `Ok(false)` when the value is absent — i.e. the
/// daemon is not running under a `Type=notify` unit, which is a normal no-op,
/// not an error. Split from [`notify`] so every branch except the raw env read
/// is unit-tested.
pub fn notify_with_socket(
    notify_socket: Option<&str>,
    states: &[NotifyState],
) -> Result<bool, NotifyError> {
    let Some(raw) = notify_socket else {
        return Ok(false);
    };
    if raw.is_empty() {
        return Ok(false);
    }
    let addr = parse_notify_socket(raw)?;
    send_notify_to(&addr, states)?;
    Ok(true)
}

/// Send an `sd_notify` message using the process's `$NOTIFY_SOCKET`. Returns
/// `Ok(false)` when the env var is unset (not under systemd notify). The single
/// `env::var` read is the only line not covered by unit tests — delivery to the
/// real systemd manager is only observable under systemd.
pub fn notify(states: &[NotifyState]) -> Result<bool, NotifyError> {
    let raw = std::env::var("NOTIFY_SOCKET").ok();
    notify_with_socket(raw.as_deref(), states)
}

/// Convenience: signal `READY=1`. Called once bootstrap completes.
pub fn notify_ready() -> Result<bool, NotifyError> {
    notify(&[NotifyState::Ready])
}

/// Derive the recommended watchdog ping interval from systemd's
/// `$WATCHDOG_USEC` value. systemd documents pinging at HALF the timeout so a
/// single missed cycle never trips the watchdog. Returns `None` when the value
/// is absent, non-numeric, or zero (watchdog disabled).
pub fn watchdog_interval(watchdog_usec: Option<&str>) -> Option<Duration> {
    let usec: u64 = watchdog_usec?.parse().ok()?;
    if usec == 0 {
        return None;
    }
    Some(Duration::from_micros(usec / 2))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    const SAMPLE_BINARY: &str = "/usr/lib/netrulerouter/nrr-serviced";

    fn sample_config() -> SystemdServiceConfig {
        SystemdServiceConfig::for_binary(PathBuf::from(SAMPLE_BINARY))
    }

    #[test]
    fn unit_declares_notify_type_and_exec_start() {
        let unit = render_service_unit(&sample_config());
        assert!(unit.contains("Type=notify"), "{unit}");
        assert!(
            unit.contains("ExecStart=/usr/lib/netrulerouter/nrr-serviced run"),
            "{unit}"
        );
        assert!(unit.contains("Description=NetRuleRouter"), "{unit}");
    }

    #[test]
    fn the_unit_description_is_the_products_own_service_name() {
        // The same line an operator sees in the Windows service list. Two
        // spellings of one service is one service too many.
        let unit = render_service_unit(&sample_config());
        assert!(
            unit.contains(&format!(
                "Description={}",
                nrr_shared::product_identity::SERVICE_DISPLAY_NAME
            )),
            "{unit}"
        );
    }

    #[test]
    fn unit_bounds_crash_recovery_instead_of_restarting_forever() {
        let unit = render_service_unit(&SystemdServiceConfig {
            restart_sec: 7,
            start_limit_burst: 3,
            start_limit_interval_sec: 600,
            ..sample_config()
        });
        assert!(unit.contains("Restart=on-failure"), "{unit}");
        assert!(unit.contains("RestartSec=7"), "{unit}");
        // The bounds belong to [Unit]; without them `Restart=` is unbounded.
        assert!(unit.contains("StartLimitBurst=3"), "{unit}");
        assert!(unit.contains("StartLimitIntervalSec=600"), "{unit}");
    }

    #[test]
    fn an_on_demand_install_writes_the_unit_without_enabling_it() {
        // "Start when the application asks" must not wire the unit into the
        // boot target — but the unit still has to be readable by systemd, so
        // daemon-reload stays.
        let plan = plan_install(&sample_config(), UnitActivation::LeaveDisabled);
        assert_eq!(
            plan.post_write_commands,
            vec![vec!["systemctl".to_string(), "daemon-reload".to_string()]]
        );
        // Everything else is identical to an enabled install.
        assert_eq!(
            plan.unit_contents,
            plan_install(&sample_config(), UnitActivation::EnableNow).unit_contents
        );
    }

    #[test]
    fn purge_targets_only_directories_the_unit_provisions() {
        // Both paths must be the ones the unit's StateDirectory=/LogsDirectory=
        // create — deleting anything else would be deleting someone else's data.
        let unit = render_service_unit(&sample_config());
        assert!(unit.contains(&format!(
            "StateDirectory={}",
            state_dir().file_name().expect("leaf").to_string_lossy()
        )));
        assert!(unit.contains(&format!(
            "LogsDirectory={}",
            log_dir().file_name().expect("leaf").to_string_lossy()
        )));
        assert_eq!(state_dir(), PathBuf::from("/var/lib/netrulerouter"));
        assert_eq!(log_dir(), PathBuf::from("/var/log/netrulerouter"));
    }

    #[test]
    fn unit_installs_to_multi_user_target() {
        let unit = render_service_unit(&sample_config());
        assert!(unit.contains("[Install]"));
        assert!(unit.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn unit_provisions_runtime_and_state_dirs_at_0700() {
        // These tie into the IPC socket (/run/netrulerouter) and the
        // DB-MAC key (/var/lib/netrulerouter).
        let unit = render_service_unit(&sample_config());
        assert!(unit.contains("RuntimeDirectory=netrulerouter"));
        assert!(unit.contains("RuntimeDirectoryMode=0700"));
        assert!(unit.contains("StateDirectory=netrulerouter"));
        assert!(unit.contains("StateDirectoryMode=0700"));
    }

    #[test]
    fn unit_provisions_the_log_dir_at_0700() {
        // /var/log/netrulerouter is nrr-storage's Linux operational `logs_dir`,
        // split out from StateDirectory per FHS. systemd owns its lifecycle.
        let unit = render_service_unit(&sample_config());
        assert!(unit.contains("LogsDirectory=netrulerouter"), "{unit}");
        assert!(unit.contains("LogsDirectoryMode=0700"), "{unit}");
    }

    #[test]
    fn unit_orders_after_network_online() {
        let unit = render_service_unit(&sample_config());
        assert!(unit.contains("After=network-online.target"));
        assert!(unit.contains("Wants=network-online.target"));
    }

    #[test]
    fn unit_emits_watchdog_only_when_configured() {
        let without = render_service_unit(&sample_config());
        assert!(!without.contains("WatchdogSec"), "{without}");

        let with = render_service_unit(&SystemdServiceConfig {
            watchdog_sec: Some(30),
            ..sample_config()
        });
        assert!(with.contains("WatchdogSec=30"), "{with}");
    }

    #[test]
    fn install_plan_targets_the_system_unit_dir_with_rendered_unit() {
        let plan = plan_install(&sample_config(), UnitActivation::EnableNow);
        assert_eq!(
            plan.unit_path,
            PathBuf::from("/etc/systemd/system/netrulerouter.service")
        );
        // The written contents are exactly the rendered unit.
        assert_eq!(plan.unit_contents, render_service_unit(&sample_config()));
        assert!(plan.unit_contents.contains("Type=notify"));
    }

    #[test]
    fn install_plan_writes_the_logrotate_backstop_dropin() {
        let plan = plan_install(&sample_config(), UnitActivation::EnableNow);
        // Exactly one additional file: the logrotate drop-in.
        assert_eq!(plan.additional_files.len(), 1);
        let dropin = &plan.additional_files[0];
        assert_eq!(dropin.path, PathBuf::from("/etc/logrotate.d/netrulerouter"));
        // World-readable /etc config.
        assert_eq!(dropin.mode, 0o644);
        // Contents are exactly what the logrotate module renders (which its own
        // tests prove is scoped to /var/log and never audit).
        assert_eq!(dropin.contents, crate::logrotate::render_logrotate_config());
        assert!(dropin.contents.contains("/var/log/netrulerouter"));
    }

    #[test]
    fn uninstall_plan_removes_every_file_and_link_install_created() {
        let install = plan_install(&sample_config(), UnitActivation::EnableNow);
        let uninstall = plan_uninstall(Some(Path::new(SAMPLE_BINARY)));
        // Whatever install put on disk — files and links alike — uninstall must
        // take back off it. A dangling alias pointing at a deleted binary is
        // exactly the debris the next installer trips over.
        let mut installed: Vec<PathBuf> = install
            .additional_files
            .iter()
            .map(|f| f.path.clone())
            .collect();
        installed.extend(install.symlinks.iter().map(|s| s.link_path.clone()));
        assert_eq!(uninstall.additional_files_to_remove, installed);
    }

    #[test]
    fn uninstall_still_works_when_the_binary_cannot_be_located() {
        // An un-removable service is a much worse outcome than a leftover
        // symlink, so an unknown binary path must not block the uninstall.
        let plan = plan_uninstall(None);
        assert_eq!(
            plan.additional_files_to_remove,
            vec![crate::logrotate::config_file()]
        );
        assert_eq!(
            plan.unit_path,
            PathBuf::from("/etc/systemd/system/netrulerouter.service")
        );
    }

    #[test]
    fn install_plan_links_the_role_alias_next_to_the_daemon() {
        let plan = plan_install(&sample_config(), UnitActivation::EnableNow);
        assert_eq!(
            plan.symlinks,
            vec![SymlinkSpec {
                link_path: PathBuf::from("/usr/lib/netrulerouter/nrr-service"),
                target: PathBuf::from(SAMPLE_BINARY),
            }],
            "the alias lets a cross-platform script name one binary on every OS"
        );
    }

    #[test]
    fn the_alias_name_comes_from_the_product_identity_not_a_literal() {
        let alias = alias_link(Path::new(SAMPLE_BINARY)).expect("daemon has an alias");
        let expected = nrr_shared::product_identity::BinaryRole::Service
            .unix_alias()
            .expect("the daemon role declares an alias");
        assert_eq!(alias.link_path.file_name().unwrap(), expected);
        // And the daemon's own file name is the one the identity declares, so a
        // rename cannot leave the unit and the alias disagreeing.
        assert_eq!(
            alias.target.file_name().unwrap(),
            nrr_shared::product_identity::BinaryRole::Service.unix_file_name()
        );
    }

    #[test]
    fn a_daemon_already_named_like_the_alias_is_not_linked_to_itself() {
        assert!(alias_link(Path::new("/usr/lib/netrulerouter/nrr-service")).is_none());
    }

    #[test]
    fn a_relative_daemon_path_produces_no_link() {
        // Otherwise the link would land wherever the installing process was
        // started from — a symlink in someone's home directory, silently.
        assert!(alias_link(Path::new("nrr-serviced")).is_none());
        assert!(alias_link(Path::new("./target/debug/nrr-serviced")).is_none());
    }

    #[test]
    fn the_unit_starts_the_same_binary_the_alias_points_at() {
        let cfg = sample_config();
        let unit = render_service_unit(&cfg);
        let alias = alias_link(&cfg.binary_path).expect("alias");
        assert!(
            unit.contains(&format!("ExecStart={} run", alias.target.display())),
            "{unit}"
        );
    }

    #[test]
    fn install_plan_reloads_then_enables_now() {
        let plan = plan_install(&sample_config(), UnitActivation::EnableNow);
        assert_eq!(
            plan.post_write_commands,
            vec![
                vec!["systemctl".to_string(), "daemon-reload".to_string()],
                vec![
                    "systemctl".to_string(),
                    "enable".to_string(),
                    "--now".to_string(),
                    "netrulerouter.service".to_string(),
                ],
            ]
        );
    }

    #[test]
    fn uninstall_plan_disables_before_removing_then_reloads() {
        let plan = plan_uninstall(Some(Path::new(SAMPLE_BINARY)));
        // Stop + disable happen while the unit file still exists.
        assert_eq!(
            plan.pre_remove_commands,
            vec![vec![
                "systemctl".to_string(),
                "disable".to_string(),
                "--now".to_string(),
                "netrulerouter.service".to_string(),
            ]]
        );
        assert_eq!(
            plan.unit_path,
            PathBuf::from("/etc/systemd/system/netrulerouter.service")
        );
        // The file is gone by the time daemon-reload runs.
        assert_eq!(
            plan.post_remove_commands,
            vec![vec!["systemctl".to_string(), "daemon-reload".to_string()]]
        );
    }

    #[test]
    fn install_and_uninstall_agree_on_the_unit_path() {
        assert_eq!(
            plan_install(&sample_config(), UnitActivation::EnableNow).unit_path,
            plan_uninstall(Some(Path::new(SAMPLE_BINARY))).unit_path
        );
    }

    #[test]
    fn notify_message_renders_single_state() {
        let bytes = render_notify_message(&[NotifyState::Ready]).expect("render");
        assert_eq!(bytes, b"READY=1");
    }

    #[test]
    fn notify_message_joins_states_with_newline() {
        let bytes = render_notify_message(&[
            NotifyState::Ready,
            NotifyState::Status("bootstrap complete".to_string()),
        ])
        .expect("render");
        assert_eq!(bytes, b"READY=1\nSTATUS=bootstrap complete");
    }

    #[test]
    fn notify_message_renders_all_variants() {
        assert_eq!(
            render_notify_message(&[NotifyState::Reloading]).unwrap(),
            b"RELOADING=1"
        );
        assert_eq!(
            render_notify_message(&[NotifyState::Stopping]).unwrap(),
            b"STOPPING=1"
        );
        assert_eq!(
            render_notify_message(&[NotifyState::Watchdog]).unwrap(),
            b"WATCHDOG=1"
        );
        assert_eq!(
            render_notify_message(&[NotifyState::MainPid(4242)]).unwrap(),
            b"MAINPID=4242"
        );
    }

    #[test]
    fn notify_message_rejects_multiline_status() {
        let err = render_notify_message(&[NotifyState::Status("a\nEVIL=1".to_string())]);
        assert!(matches!(err, Err(NotifyError::MalformedStatus)));
    }

    #[test]
    fn parse_pathname_socket() {
        assert_eq!(
            parse_notify_socket("/run/systemd/notify").unwrap(),
            NotifyAddress::Path(PathBuf::from("/run/systemd/notify"))
        );
    }

    #[test]
    fn parse_abstract_socket_strips_at_sign() {
        assert_eq!(
            parse_notify_socket("@abstract-notify").unwrap(),
            NotifyAddress::Abstract("abstract-notify".to_string())
        );
    }

    #[test]
    fn parse_rejects_empty_and_relative() {
        assert!(matches!(
            parse_notify_socket(""),
            Err(NotifyError::UnsupportedAddress(_))
        ));
        assert!(matches!(
            parse_notify_socket("relative/path"),
            Err(NotifyError::UnsupportedAddress(_))
        ));
    }

    /// Unique temp socket path with best-effort cleanup, so parallel test runs
    /// never collide.
    struct TempSock(PathBuf);
    impl Drop for TempSock {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    fn temp_sock_path() -> TempSock {
        static N: AtomicU32 = AtomicU32::new(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "nrr-sd-notify-test-{}-{}.sock",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&p);
        TempSock(p)
    }

    #[test]
    fn send_notify_to_delivers_datagram_to_a_receiver() {
        // Stand in for the systemd manager: bind a receiver datagram socket and
        // assert the exact bytes arrive. Proves the real AF_UNIX send path, not
        // just message construction.
        let sock = temp_sock_path();
        let receiver = UnixDatagram::bind(&sock.0).expect("bind receiver");

        send_notify_to(
            &NotifyAddress::Path(sock.0.clone()),
            &[NotifyState::Ready, NotifyState::Status("up".to_string())],
        )
        .expect("send");

        let mut buf = [0u8; 128];
        let n = receiver.recv(&mut buf).expect("recv");
        assert_eq!(&buf[..n], b"READY=1\nSTATUS=up");
    }

    #[test]
    fn notify_with_socket_none_is_noop_ok_false() {
        // No NOTIFY_SOCKET → not under systemd notify → Ok(false), no send.
        assert!(!notify_with_socket(None, &[NotifyState::Ready]).unwrap());
        assert!(!notify_with_socket(Some(""), &[NotifyState::Ready]).unwrap());
    }

    #[test]
    fn notify_with_socket_sends_and_reports_true() {
        let sock = temp_sock_path();
        let receiver = UnixDatagram::bind(&sock.0).expect("bind receiver");
        let addr = sock.0.to_str().expect("utf8 path").to_string();

        let sent = notify_with_socket(Some(&addr), &[NotifyState::Ready]).expect("notify");
        assert!(sent);

        let mut buf = [0u8; 64];
        let n = receiver.recv(&mut buf).expect("recv");
        assert_eq!(&buf[..n], b"READY=1");
    }

    #[test]
    fn watchdog_interval_is_half_the_timeout() {
        assert_eq!(
            watchdog_interval(Some("30000000")),
            Some(Duration::from_micros(15_000_000))
        );
    }

    #[test]
    fn watchdog_interval_absent_or_zero_or_garbage_is_none() {
        assert_eq!(watchdog_interval(None), None);
        assert_eq!(watchdog_interval(Some("0")), None);
        assert_eq!(watchdog_interval(Some("not-a-number")), None);
    }
}
