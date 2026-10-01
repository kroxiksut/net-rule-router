//! Service lifecycle primitives that the SCM/console
//! entrypoint binary in `nrr-windows-service` plugs into.
//!
//! Two layers:
//!
//! 1. Identity / install metadata constants. Single source of truth so
//!    the SCM install hook, the Event Log source registration and any
//!    smoke script all see the same names.
//! 2. Process-internal lifecycle wiring: `StopToken` (cooperative
//!    cancellation handed to background tasks), the teardown latch and the
//!    `ServiceController` trait (status reporter, so console and SCM mode
//!    share `run_supervised_runtime`).
//!
//! The crate has no `windows-service` / `windows-sys` dependency: the
//! Windows adapters live in `nrr-windows-service` and implement the trait.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::state::ServiceRuntimeState;

// ── Service identity / install metadata ──────────────────────────────────────

/// Internal service name used by SCM. Stable across versions — changing it
/// breaks every operator script. Derived from the product identity so this
/// name cannot drift away from the systemd unit name or the installer.
pub const SERVICE_NAME: &str = nrr_shared::product_identity::WINDOWS_SERVICE_NAME;

/// Display name shown in the Services MMC console.
pub const SERVICE_DISPLAY_NAME: &str = nrr_shared::product_identity::WINDOWS_SERVICE_DISPLAY_NAME;

/// Description shown in the Services MMC console.
pub const SERVICE_DESCRIPTION: &str = nrr_shared::product_identity::WINDOWS_SERVICE_DESCRIPTION;

/// Event Log source name registered under
/// `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\<source>`
/// during install. Used by the SCM-mode `ReportEvent` writer.
pub const EVENT_SOURCE_NAME: &str = nrr_shared::product_identity::WINDOWS_EVENT_SOURCE_NAME;

/// Maximum time `Stopping` is allowed before background tasks are
/// detached and the process exits. Apply locks must be released
/// before this fires, enforced by a watchdog.
///
/// Sized to fit INSIDE the SCM / `stop` CLI stop window
/// (`scm::stop_service(15)` waits 15 s for `STOPPED`). A cooperative task
/// honours the stop token within tens of milliseconds; one still running
/// after a few seconds is blocked on a non-cooperative syscall (e.g. a
/// synchronous named-pipe accept) and will not drain even at 30 s, so
/// waiting longer only delays the inevitable detach past the client's
/// budget. Detaching at 5 s lets the runtime report `Stopped` and exit 0
/// well within the window; detached stragglers die with the process
/// (each holds its own `Arc`, so detach is memory-safe).
pub const STOP_TIMEOUT: Duration = Duration::from_secs(5);

// ── Stop token ────────────────────────────────────────────────────────────────

/// Cooperative cancellation handle. Cloned freely; flipping it via
/// `request_stop()` makes every clone observe `is_stop_requested() ==
/// true`. Used by background tasks (refresh watcher, IPC
/// listener, runtime loop) to bail out promptly when
/// SCM sends `Stop`.
#[derive(Clone, Debug)]
pub struct StopToken {
    flag: Arc<AtomicBool>,
}

impl StopToken {
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Signal every clone of this token to stop. Idempotent.
    pub fn request_stop(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// Whether `request_stop()` has been called on any clone.
    pub fn is_stop_requested(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

impl Default for StopToken {
    fn default() -> Self {
        Self::new()
    }
}

// ── Teardown latch ───────────────────────────────────────────────────────────

/// Process-wide "the stop teardown has begun" latch.
///
/// The stop token alone is not enough: background workers that were never
/// handed a clone of it (the fake-IP watchdog, the debounced network-change
/// re-arm) can still re-install routes and WFP filters *after* the teardown
/// stripped them — and those survive the process, because the WFP session is
/// non-dynamic. Anything that enforces must check this before it applies.
static TEARDOWN_STARTED: AtomicBool = AtomicBool::new(false);

/// Latch the teardown. Called once, right after the stop token flips.
pub fn begin_teardown() {
    TEARDOWN_STARTED.store(true, Ordering::SeqCst);
}

/// Whether stop teardown has begun. Enforcement work must bail out on `true`.
pub fn teardown_in_progress() -> bool {
    TEARDOWN_STARTED.load(Ordering::SeqCst)
}

/// Clear the latch at runtime start so a second runtime in the same process
/// (tests, console-mode restart) is not born already tearing down.
pub fn clear_teardown() {
    TEARDOWN_STARTED.store(false, Ordering::SeqCst);
}

// ── Service controller trait ─────────────────────────────────────────────────

/// Status-reporter abstraction. SCM mode implements this with
/// `windows-service`'s `ServiceStatusHandle`; console mode implements
/// it with `eprintln!` so dev builds get the same observability without
/// the SCM glue. The runtime body never knows which side it talks to.
pub trait ServiceController: Send + Sync {
    /// Report a runtime state to the controller. Maps internally to
    /// the SCM `ServiceState` enum.
    /// `Degraded` and `RecoveryRequired` map to `Running` at the SCM
    /// level (no native equivalent); the GUI sees the real severity
    /// via the `HealthReporter`.
    fn report(&self, state: ServiceRuntimeState);
}

// TODO: Windows Event Log writer — Start/Stop/Degraded/Critical transitions
// need a `windows-sys::ReportEventW` writer in `nrr-windows-service` (install
// already registers the source); this crate keeps only the trait surface so
// the runtime body stays transport-agnostic.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_token_is_observed_by_clones() {
        let token = StopToken::new();
        let clone = token.clone();
        assert!(!clone.is_stop_requested());
        token.request_stop();
        assert!(clone.is_stop_requested());
    }
}
