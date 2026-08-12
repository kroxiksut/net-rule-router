//! Neutral service-control port — register, remove, start, stop and inspect the
//! background service.
//!
//! This is the *mechanism* half of the seam: the OS backends
//! (`nrr-platform-windows` over SCM, `nrr-platform-linux` over systemd) provide
//! the implementation, while every caller — the administrative console, the
//! service binary's own verbs, the elevation broker — codes against the trait.
//! The *policy* half (which verb a user may run, what a failure prints, which
//! exit code it maps to) stays in the caller and is tested once, without an OS.
//!
//! Deliberately NOT part of this port:
//!
//! - **Diagnostics export before uninstall.** Building the archive is a flow
//!   step owned by the caller, not an OS mechanism; keeping it out is what lets
//!   this trait live below the orchestration layer instead of dragging it in.
//! - **Binary replacement / update.** An update is "stop, swap the file, start"
//!   — three steps the caller composes from the verbs below.

use std::path::PathBuf;
use std::time::Duration;

// ── Start mode ───────────────────────────────────────────────────────────────

/// How the service is launched by the OS.
///
/// The slugs are part of the GUI/wire round-trip and predate the cross-platform
/// split, so they keep their original spelling: `with-windows` means "start with
/// the operating system" (SCM `SERVICE_AUTO_START`, systemd `enable`), and
/// `on-app-launch` means "start on demand when the app opens" (SCM
/// `SERVICE_DEMAND_START`, systemd socket/manual activation).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ServiceStartMode {
    /// Start with the operating system (the default).
    #[default]
    WithWindows,
    /// Start when the application is launched (opt-in, requires an
    /// administrator to grant the interactive user the targeted start right).
    OnAppLaunch,
}

impl ServiceStartMode {
    /// Stable slug for the console argument and the wire/GUI round-trip.
    pub fn slug(self) -> &'static str {
        match self {
            Self::WithWindows => "with-windows",
            Self::OnAppLaunch => "on-app-launch",
        }
    }

    /// Parse a slug. Accepts the canonical form plus the short `auto` /
    /// `demand` / `on-demand` aliases so the console is forgiving.
    pub fn from_slug(s: &str) -> Option<Self> {
        match s {
            "with-windows" | "auto" => Some(Self::WithWindows),
            "on-app-launch" | "demand" | "on-demand" => Some(Self::OnAppLaunch),
            _ => None,
        }
    }
}

// ── Recovery policy ──────────────────────────────────────────────────────────

/// How the OS should recover the service from crashes.
///
/// Wired into SCM failure actions on Windows and `Restart=`/`RestartSec=` on
/// systemd. The policy avoids infinite restart loops by stopping automatic
/// recovery after `max_auto_restarts` consecutive failures within the reset
/// window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryPolicy {
    /// Delay (ms) before the first auto-restart after a crash.
    pub first_restart_delay_ms: u32,
    /// Delay (ms) before the second auto-restart.
    pub second_restart_delay_ms: u32,
    /// Number of consecutive crashes that trigger automatic restart. Crashes
    /// beyond this leave the service stopped for operator review.
    pub max_auto_restarts: u8,
    /// How long (seconds) the crash counter is held before resetting.
    pub reset_period_secs: u32,
}

impl RecoveryPolicy {
    /// Default production policy: restart twice with escalating delay; stop on
    /// the third crash and require operator intervention.
    pub const fn production() -> Self {
        Self {
            first_restart_delay_ms: 5_000,
            second_restart_delay_ms: 30_000,
            max_auto_restarts: 2,
            reset_period_secs: 86_400, // 24 h
        }
    }

    /// Aggressive dev policy: restart quickly, higher tolerance.
    pub const fn dev() -> Self {
        Self {
            first_restart_delay_ms: 1_000,
            second_restart_delay_ms: 5_000,
            max_auto_restarts: 5,
            reset_period_secs: 3_600, // 1 h
        }
    }
}

// ── Install ──────────────────────────────────────────────────────────────────

/// Everything the OS needs in order to register the service.
#[derive(Clone, Debug)]
pub struct ServiceInstallSpec {
    /// Absolute path to the service binary to register.
    pub binary_path: PathBuf,
    /// Recovery policy to configure immediately after registration.
    pub recovery: RecoveryPolicy,
    /// Start mode to register. Switching afterwards goes through the dedicated
    /// reconfigure path, not through a re-install.
    pub start_mode: ServiceStartMode,
    /// Service account to run as. `None` inherits the installer's identity,
    /// which is the full-privilege system account in practice.
    pub account_name: Option<String>,
    /// Whether the install flow should create the service-owned data directory
    /// tree (and lock down its permissions).
    pub create_data_dirs: bool,
}

impl ServiceInstallSpec {
    /// Production defaults for a binary at `binary_path`.
    pub fn production_defaults(binary_path: PathBuf) -> Self {
        Self {
            binary_path,
            recovery: RecoveryPolicy::production(),
            account_name: None,
            create_data_dirs: true,
            start_mode: ServiceStartMode::WithWindows,
        }
    }
}

/// What an install actually did.
#[derive(Clone, Debug, Default)]
pub struct ServiceInstallReport {
    /// Directories created by this install.
    pub data_dirs_created: Vec<PathBuf>,
    /// Whether OS-level crash recovery was configured successfully.
    pub recovery_configured: bool,
    /// Whether the data directory's permissions were tightened to the security
    /// baseline. `None` when the install was asked not to create data dirs, so
    /// it never touched their permissions either.
    pub acl_applied: Option<bool>,
}

// ── Uninstall ────────────────────────────────────────────────────────────────

/// What the OS should remove.
///
/// Note what is absent: whether to export diagnostics first. That is a flow
/// decision made — and executed — by the caller before it asks the OS to
/// deregister anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceUninstallSpec {
    /// When `true`, the service-owned data directory tree is deleted after the
    /// service registration is removed.
    pub remove_service_owned_data: bool,
}

impl ServiceUninstallSpec {
    /// Deregister the service but leave every file in place.
    pub const fn keep_data() -> Self {
        Self {
            remove_service_owned_data: false,
        }
    }

    /// Deregister and delete the service-owned data tree. User-owned rule files
    /// live outside that tree and are never touched by this.
    pub const fn purge_data() -> Self {
        Self {
            remove_service_owned_data: true,
        }
    }
}

/// What an uninstall actually did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServiceUninstallReport {
    /// Whether the service-owned data directory was deleted.
    pub data_removed: bool,
}

// ── Status ───────────────────────────────────────────────────────────────────

/// Coarse run state, uniform across service managers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceRunState {
    /// Registered but not running.
    Stopped,
    /// Starting up.
    StartPending,
    /// Running.
    Running,
    /// Shutting down.
    StopPending,
    /// The manager reported a state this port does not model.
    Other,
}

impl ServiceRunState {
    /// Lower-case slug for console output.
    pub fn slug(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::StartPending => "start-pending",
            Self::Running => "running",
            Self::StopPending => "stop-pending",
            Self::Other => "unknown",
        }
    }
}

/// A single, cheap snapshot of the service registration. Answering this must
/// not require talking to the running service — it is the question a user asks
/// precisely when the service is NOT answering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceStatusReport {
    /// Run state as reported by the service manager.
    pub run_state: ServiceRunState,
    /// Registered start mode, when the manager exposes it.
    pub start_mode: Option<ServiceStartMode>,
    /// Registered binary path, when the manager exposes it.
    pub binary_path: Option<PathBuf>,
}

// ── Errors ───────────────────────────────────────────────────────────────────

/// Why a service-control operation could not be completed.
///
/// The taxonomy exists so callers can map failures onto stable exit codes and
/// actionable messages without parsing OS error strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceControlError {
    /// The service is not registered with the service manager.
    NotInstalled,
    /// The caller lacks the privilege the operation requires.
    AccessDenied,
    /// The service manager refused because the service is already in the
    /// requested state or mid-transition.
    InvalidState { detail: String },
    /// The operation was accepted but the service did not reach the expected
    /// state within the caller's budget.
    Timeout {
        operation: &'static str,
        seconds: u64,
    },
    /// The operation has no implementation on this platform.
    Unsupported { operation: &'static str },
    /// Anything else the OS reported, verbatim.
    Mechanism { detail: String },
}

impl std::fmt::Display for ServiceControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInstalled => write!(f, "service is not installed"),
            Self::AccessDenied => write!(f, "access denied"),
            Self::InvalidState { detail } => write!(f, "invalid service state: {detail}"),
            Self::Timeout { operation, seconds } => {
                write!(f, "{operation} did not complete within {seconds}s")
            }
            Self::Unsupported { operation } => {
                write!(f, "{operation} is not supported on this platform")
            }
            Self::Mechanism { detail } => write!(f, "{detail}"),
        }
    }
}

impl std::error::Error for ServiceControlError {}

// ── The port ─────────────────────────────────────────────────────────────────

/// Register, remove, run and inspect the background service.
///
/// Implementations talk to exactly one service manager and hold no state beyond
/// the identity of the service they control.
pub trait ServiceControlPort {
    /// Register the service. Requires administrator/root privilege.
    fn install(
        &self,
        spec: &ServiceInstallSpec,
    ) -> Result<ServiceInstallReport, ServiceControlError>;

    /// Deregister the service, stopping it first if it is running. Requires
    /// administrator/root privilege.
    fn uninstall(
        &self,
        spec: &ServiceUninstallSpec,
    ) -> Result<ServiceUninstallReport, ServiceControlError>;

    /// Start the service and wait up to `timeout` for it to come up. Returning
    /// `Ok` while the service is still start-pending is allowed: the transition
    /// is monitored by whoever polls status afterwards.
    fn start(&self, timeout: Duration) -> Result<(), ServiceControlError>;

    /// Stop the service and wait up to `timeout` for it to go down. Stopping an
    /// already-stopped service succeeds.
    fn stop(&self, timeout: Duration) -> Result<(), ServiceControlError>;

    /// Stop then start, in one call, so a privilege prompt is raised once
    /// instead of twice.
    fn restart(&self, timeout: Duration) -> Result<(), ServiceControlError> {
        self.stop(timeout)?;
        self.start(timeout)
    }

    /// Read the current registration. `Ok(None)` means "not installed" — an
    /// ordinary answer to a status question, not a failure.
    fn query(&self) -> Result<Option<ServiceStatusReport>, ServiceControlError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_mode_slug_round_trips_with_aliases() {
        for mode in [ServiceStartMode::WithWindows, ServiceStartMode::OnAppLaunch] {
            assert_eq!(ServiceStartMode::from_slug(mode.slug()), Some(mode));
        }
        assert_eq!(
            ServiceStartMode::from_slug("auto"),
            Some(ServiceStartMode::WithWindows)
        );
        assert_eq!(
            ServiceStartMode::from_slug("demand"),
            Some(ServiceStartMode::OnAppLaunch)
        );
        assert_eq!(
            ServiceStartMode::from_slug("on-demand"),
            Some(ServiceStartMode::OnAppLaunch)
        );
        assert_eq!(ServiceStartMode::from_slug("nonsense"), None);
    }

    #[test]
    fn start_mode_default_is_start_with_the_os() {
        assert_eq!(ServiceStartMode::default(), ServiceStartMode::WithWindows);
    }

    #[test]
    fn production_recovery_policy_cannot_loop_forever() {
        let p = RecoveryPolicy::production();
        assert!(p.max_auto_restarts > 0, "must restart at least once");
        assert!(
            p.max_auto_restarts <= 5,
            "must stop auto-restart before an infinite loop"
        );
        assert!(
            p.first_restart_delay_ms > 0,
            "an immediate restart amplifies crash loops"
        );
        assert!(
            p.second_restart_delay_ms >= p.first_restart_delay_ms,
            "the delay must escalate"
        );
        assert!(p.reset_period_secs > 0, "the reset period must be finite");
    }

    #[test]
    fn install_defaults_create_data_dirs_and_start_with_the_os() {
        let spec = ServiceInstallSpec::production_defaults(PathBuf::from("nrr-service.exe"));
        assert!(spec.create_data_dirs);
        assert_eq!(spec.start_mode, ServiceStartMode::WithWindows);
        assert_eq!(spec.recovery, RecoveryPolicy::production());
    }

    #[test]
    fn uninstall_specs_say_exactly_what_they_do() {
        assert!(!ServiceUninstallSpec::keep_data().remove_service_owned_data);
        assert!(ServiceUninstallSpec::purge_data().remove_service_owned_data);
    }

    #[test]
    fn run_state_slugs_are_distinct_and_lowercase() {
        let all = [
            ServiceRunState::Stopped,
            ServiceRunState::StartPending,
            ServiceRunState::Running,
            ServiceRunState::StopPending,
            ServiceRunState::Other,
        ];
        let mut slugs: Vec<&str> = all.iter().map(|s| s.slug()).collect();
        let count = slugs.len();
        slugs.sort_unstable();
        slugs.dedup();
        assert_eq!(slugs.len(), count);
        for slug in slugs {
            assert_eq!(slug, slug.to_ascii_lowercase());
        }
    }
}
