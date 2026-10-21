//! Keeps confirmed overrides honest about the service accounts they cover.
//!
//! A confirmation lists the service accounts running what its rule takes when
//! it is given. A service installed later may run the same programs, so the
//! list is read again: at start, when the OS reports the set of services
//! changed, and on a slow timer for platforms or moments without an event.
//! Never on an enforcement pass. A rule that now takes an account its
//! confirmation did not list waits for a new confirmation.
//!
//! The same thread tells users a withdrawal that happened before any of their
//! clients was connected.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use nrr_platform_api::network_change::NetworkChangeSubscription;
use nrr_platform_api::service_set_change::ServiceSetChangeObserver;

use crate::ipc_handlers::{service_accounts_reader, RuleOverrideDeps};
use crate::service_tasks::ServiceTaskKind;
use crate::task_liveness::{TaskLiveness, ThreadExit, ThreadLease, Watch};
use crate::timed_window::now_ms;

/// How the thread paces itself.
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    /// The accounts are read again this often with no event to say so.
    pub interval: Duration,
    /// Events closer together than this are one re-check.
    pub settle: Duration,
    /// How often the thread looks for a withdrawal to tell.
    pub tell_every: Duration,
}

impl Timing {
    pub const SERVICE: Self = Self {
        interval: Duration::from_secs(10 * 60),
        settle: Duration::from_secs(2),
        tell_every: Duration::from_secs(5),
    };
}

struct Signal {
    poked: Mutex<bool>,
    cv: Condvar,
    stop: AtomicBool,
}

/// The re-check thread and its event subscription.
pub struct OverrideRecheck {
    signal: Arc<Signal>,
    thread: Option<JoinHandle<()>>,
    _subscription: Option<NetworkChangeSubscription>,
}

static RUNNING: OnceLock<OverrideRecheck> = OnceLock::new();

/// The service's health board, handed over once it exists: on Linux the
/// thread starts before it.
static LIVENESS: OnceLock<Arc<TaskLiveness>> = OnceLock::new();

/// The loop wakes every `tell_every`; this much silence is a stuck thread.
const SILENCE: Duration = Duration::from_secs(60);

/// Report the thread's life to `liveness`. The first call wins.
pub fn report_to(liveness: Arc<TaskLiveness>) {
    let _ = LIVENESS.set(liveness);
}

/// Start the service's re-check for the life of the process. Only the first
/// call counts.
pub fn start_for_service(deps: Arc<RuleOverrideDeps>, observer: &dyn ServiceSetChangeObserver) {
    let _ = RUNNING.set(OverrideRecheck::start(deps, observer, Timing::SERVICE));
}

/// One re-check: how many confirmations went back to waiting.
pub fn recheck_once(deps: &RuleOverrideDeps) -> usize {
    let mut reader = service_accounts_reader(deps);
    deps.grants.recheck_accounts(&mut reader, now_ms())
}

impl OverrideRecheck {
    /// Re-check now, on every event `observer` reports, and at least every
    /// `timing.interval`.
    pub fn start(
        deps: Arc<RuleOverrideDeps>,
        observer: &dyn ServiceSetChangeObserver,
        timing: Timing,
    ) -> Self {
        let signal = Arc::new(Signal {
            poked: Mutex::new(false),
            cv: Condvar::new(),
            stop: AtomicBool::new(false),
        });
        let subscription = {
            let signal = Arc::clone(&signal);
            observer
                .subscribe(Arc::new(move || signal.poke()))
                .map_err(|e| {
                    tracing::warn!(
                        target: "nrr::override",
                        msg_key = "service-set-watch-unavailable",
                        error = %e,
                        "installed services are not watched; confirmed overrides are re-checked on a timer",
                    );
                })
                .ok()
        };
        let thread = {
            let signal = Arc::clone(&signal);
            std::thread::Builder::new()
                .name("nrr-override-recheck".to_string())
                .spawn(move || run(&deps, &signal, timing))
                .ok()
        };
        Self {
            signal,
            thread,
            _subscription: subscription,
        }
    }
}

impl Drop for OverrideRecheck {
    fn drop(&mut self) {
        self.signal.stop.store(true, Ordering::Release);
        self.signal.poke();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Signal {
    fn poke(&self) {
        *self.poked.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.cv.notify_all();
    }

    /// Let a burst of events end before the machine is read. `false` when asked
    /// to stop meanwhile.
    fn settle(&self, limit: Duration) -> bool {
        let until = Instant::now() + limit;
        while let Some(left) = until.checked_duration_since(Instant::now()) {
            if self.stop.load(Ordering::Acquire) {
                return false;
            }
            std::thread::sleep(left.min(Duration::from_millis(100)));
        }
        !self.stop.load(Ordering::Acquire)
    }

    /// Wait up to `limit`; whether an event arrived meanwhile.
    fn wait(&self, limit: Duration) -> bool {
        let guard = self.poked.lock().unwrap_or_else(PoisonError::into_inner);
        let (mut guard, _) = self
            .cv
            .wait_timeout_while(guard, limit, |poked| {
                !*poked && !self.stop.load(Ordering::Acquire)
            })
            .unwrap_or_else(PoisonError::into_inner);
        std::mem::take(&mut *guard)
    }
}

fn run(deps: &RuleOverrideDeps, signal: &Signal, timing: Timing) {
    let mut last = Instant::now();
    let mut first = true;
    let mut lease: Option<ThreadLease> = None;
    loop {
        let poked =
            std::mem::take(&mut first) || signal.wait(timing.tell_every.min(timing.interval));
        if signal.stop.load(Ordering::Acquire) {
            if let Some(lease) = lease.take() {
                lease.finish(ThreadExit::Stopped);
            }
            return;
        }
        if lease.is_none() {
            lease = LIVENESS.get().map(|board| {
                board.lease(
                    ServiceTaskKind::OverrideRecheck,
                    None,
                    Watch::Beats(SILENCE),
                )
            });
        }
        if let Some(lease) = lease.as_ref() {
            lease.beat();
        }
        deps.grants.deliver_unheard();
        if !poked && last.elapsed() < timing.interval {
            continue;
        }
        if poked && !signal.settle(timing.settle) {
            if let Some(lease) = lease.take() {
                lease.finish(ThreadExit::Stopped);
            }
            return;
        }
        recheck_once(deps);
        last = Instant::now();
    }
}

#[cfg(test)]
mod tests;
