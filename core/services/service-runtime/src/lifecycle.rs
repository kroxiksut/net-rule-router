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

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::lifecycle_matrix::StopReason;
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
    inner: Arc<StopSignal>,
}

#[derive(Debug, Default)]
struct StopSignal {
    flag: AtomicBool,
    /// The first reason given; a stop followed by a shutdown is still the
    /// stop that began the teardown.
    reason: AtomicU8,
    /// Wakes the sleepers in [`StopToken::wait_for`]. A sleeper that polled the
    /// flag instead woke twenty times a second per thread, on every idle task.
    lock: Mutex<()>,
    wake: Condvar,
}

const REASON_NONE: u8 = 0;
const REASON_SERVICE_STOP: u8 = 1;
const REASON_MACHINE_SHUTDOWN: u8 = 2;
const REASON_UPGRADE: u8 = 3;

fn encode_reason(reason: StopReason) -> u8 {
    match reason {
        StopReason::ServiceStop => REASON_SERVICE_STOP,
        StopReason::MachineShutdown => REASON_MACHINE_SHUTDOWN,
        StopReason::Upgrade => REASON_UPGRADE,
    }
}

fn decode_reason(code: u8) -> Option<StopReason> {
    match code {
        REASON_SERVICE_STOP => Some(StopReason::ServiceStop),
        REASON_MACHINE_SHUTDOWN => Some(StopReason::MachineShutdown),
        REASON_UPGRADE => Some(StopReason::Upgrade),
        _ => None,
    }
}

impl StopToken {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(StopSignal::default()),
        }
    }

    /// Signal every clone of this token to stop, waking every sleeper.
    /// Idempotent. A plain stop: the machine keeps running.
    pub fn request_stop(&self) {
        self.request_stop_for(StopReason::ServiceStop);
    }

    /// [`Self::request_stop`] with the reason the teardown reads.
    pub fn request_stop_for(&self, reason: StopReason) {
        let _ = self.inner.reason.compare_exchange(
            REASON_NONE,
            encode_reason(reason),
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        self.inner.flag.store(true, Ordering::SeqCst);
        // Taken so a sleeper between its flag check and its wait cannot miss
        // the notification.
        let _guard = self.inner.lock.lock().unwrap_or_else(|p| p.into_inner());
        self.inner.wake.notify_all();
    }

    /// Whether `request_stop()` has been called on any clone.
    pub fn is_stop_requested(&self) -> bool {
        self.inner.flag.load(Ordering::SeqCst)
    }

    /// Why the stop was requested; `None` while no stop is requested.
    pub fn stop_reason(&self) -> Option<StopReason> {
        decode_reason(self.inner.reason.load(Ordering::SeqCst))
    }

    /// Sleep up to `total`, returning early — at once — when a stop is
    /// requested. Returns whether it was.
    pub fn wait_for(&self, total: Duration) -> bool {
        let deadline = Instant::now() + total;
        let mut guard = self.inner.lock.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if self.is_stop_requested() {
                return true;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            guard = self
                .inner
                .wake
                .wait_timeout(guard, remaining)
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
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
static TEARDOWN_REASON: AtomicU8 = AtomicU8::new(REASON_NONE);

/// A start that cannot reach `Running`. Read by the IPC router: reads are
/// answered so the reason can be shown, everything that changes state is
/// refused.
static RECOVERY_REQUIRED: AtomicBool = AtomicBool::new(false);

/// Latch the teardown. Called once, right after the stop token flips.
pub fn begin_teardown() {
    begin_teardown_for(StopReason::ServiceStop);
}

/// [`begin_teardown`] with the reason the teardown hooks plan by.
pub fn begin_teardown_for(reason: StopReason) {
    TEARDOWN_REASON.store(encode_reason(reason), Ordering::SeqCst);
    TEARDOWN_STARTED.store(true, Ordering::SeqCst);
}

/// Whether stop teardown has begun. Enforcement work must bail out on `true`.
pub fn teardown_in_progress() -> bool {
    TEARDOWN_STARTED.load(Ordering::SeqCst)
}

/// Why the teardown runs. A service stop until a teardown says otherwise.
pub fn teardown_reason() -> StopReason {
    decode_reason(TEARDOWN_REASON.load(Ordering::SeqCst)).unwrap_or(StopReason::ServiceStop)
}

/// The file a package upgrade leaves in the service's data directory before it
/// restarts the daemon: the stop is the upgrade's (`StopReason::Upgrade`).
/// The directory is the root-only state root, so nobody else can plant it.
pub const UPGRADE_STOP_MARKER: &str = "upgrade-stop";

/// How long the marker speaks for a stop: an upgrade that never stopped the
/// daemon must not make a later stop keep its blocks.
const UPGRADE_STOP_FRESHNESS: std::time::Duration = std::time::Duration::from_secs(120);

/// Whether the stop under way is a package upgrade's. Consumes the marker; a
/// stale one, or anything but a plain file, counts for nothing.
pub fn take_upgrade_stop_marker(data_dir: &std::path::Path) -> bool {
    let path = data_dir.join(UPGRADE_STOP_MARKER);
    let fresh = std::fs::symlink_metadata(&path)
        .ok()
        .filter(std::fs::Metadata::is_file)
        .and_then(|meta| meta.modified().ok())
        .and_then(|at| at.elapsed().ok())
        .is_some_and(|age| age <= UPGRADE_STOP_FRESHNESS);
    let _ = std::fs::remove_file(&path);
    fresh
}

/// Clear the latch at runtime start so a second runtime in the same process
/// (tests, console-mode restart) is not born already tearing down.
pub fn clear_teardown() {
    TEARDOWN_STARTED.store(false, Ordering::SeqCst);
    TEARDOWN_REASON.store(REASON_NONE, Ordering::SeqCst);
    RECOVERY_REQUIRED.store(false, Ordering::SeqCst);
}

/// Mark this run as one that never reached `Running`.
pub fn mark_recovery_required() {
    RECOVERY_REQUIRED.store(true, Ordering::SeqCst);
}

/// Whether this run is parked in recovery.
pub fn recovery_required() -> bool {
    RECOVERY_REQUIRED.load(Ordering::SeqCst)
}

/// The run is over; a later runtime in this process starts clean.
pub fn clear_recovery_required() {
    RECOVERY_REQUIRED.store(false, Ordering::SeqCst);
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

    /// A package upgrade marks its stop; the marker is read once, and a link
    /// planted under the name never counts.
    #[test]
    fn an_upgrade_marker_speaks_for_one_stop_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(!take_upgrade_stop_marker(dir.path()));
        std::fs::write(dir.path().join(UPGRADE_STOP_MARKER), b"").expect("mark");
        assert!(take_upgrade_stop_marker(dir.path()));
        assert!(!take_upgrade_stop_marker(dir.path()), "consumed");
        #[cfg(unix)]
        {
            let target = dir.path().join("elsewhere");
            std::fs::write(&target, b"").expect("target");
            std::os::unix::fs::symlink(&target, dir.path().join(UPGRADE_STOP_MARKER))
                .expect("link");
            assert!(!take_upgrade_stop_marker(dir.path()));
        }
    }

    /// A sleeper wakes on the stop itself, not on its next poll — and without
    /// one, sleeps out its time instead of spinning.
    #[test]
    fn a_sleeper_wakes_at_once_on_stop_and_not_before() {
        let token = StopToken::new();
        let started = Instant::now();
        assert!(!token.wait_for(Duration::from_millis(30)));
        assert!(started.elapsed() >= Duration::from_millis(30));

        let sleeper = {
            let token = token.clone();
            std::thread::spawn(move || {
                let started = Instant::now();
                (token.wait_for(Duration::from_secs(30)), started.elapsed())
            })
        };
        std::thread::sleep(Duration::from_millis(50));
        token.request_stop();
        let (stopped, slept) = sleeper.join().expect("sleeper");
        assert!(stopped);
        assert!(slept < Duration::from_secs(5), "woke only at its deadline");
        assert!(
            token.wait_for(Duration::from_secs(30)),
            "a stopped token sleeps"
        );
    }

    #[test]
    fn stop_token_is_observed_by_clones() {
        let token = StopToken::new();
        let clone = token.clone();
        assert!(!clone.is_stop_requested());
        token.request_stop();
        assert!(clone.is_stop_requested());
    }

    #[test]
    fn the_first_stop_reason_is_the_one_the_teardown_reads() {
        let token = StopToken::new();
        assert_eq!(token.stop_reason(), None);
        token.request_stop_for(StopReason::MachineShutdown);
        token.request_stop();
        assert_eq!(token.stop_reason(), Some(StopReason::MachineShutdown));
        assert_eq!(StopToken::new().stop_reason(), None);
        let plain = StopToken::new();
        plain.request_stop();
        assert_eq!(plain.stop_reason(), Some(StopReason::ServiceStop));
    }
}
