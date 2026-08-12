//! Resume-from-sleep re-arm.
//!
//! A laptop wakes with a binding resolved against a network that no longer
//! exists: the tunnel adapter it slept with is down, renamed, or re-created
//! under a new identity. Nothing in the event-driven path fires — the OS
//! notifications that would have reported the change happened while we were not
//! running, and the adapter monitor only reacts to a *transition* it can
//! observe. The result is a machine sitting fail-closed until some unrelated
//! event finally arrives.
//!
//! Two independent signals converge here on one debounced re-arm:
//!
//! - the platform [`PowerEventObserver`] (prompt, per-OS mechanism), and
//! - a neutral wall-clock gap detector that needs no OS support at all: while
//!   the machine sleeps, the wall clock advances and the monotonic clock does
//!   not, so a divergence between the two is time we spent not running.
//!
//! The same re-arm serves the fail-closed heartbeat via [`RebindRequests`]: a
//! posture that has been blocking for minutes asks for a fresh resolution
//! instead of only announcing itself.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use nrr_platform_api::error::PlatformError;
use nrr_platform_api::power::{PowerEvent, PowerEventObserver, PowerEventSubscription};

use crate::network_rearm::DebouncedTrigger;
use crate::runtime_loop::{ServiceTask, TaskClass, TaskOutcome};
use crate::service_tasks::RECOVERABLE_DEFAULT_MAX_RESTARTS;

/// Coalescing window for resume signals. Wider than the network-change window:
/// a wake produces a burst of adapter/route churn for a few seconds, and
/// re-arming into the middle of it just wastes a pass.
pub const RESUME_DEBOUNCE: Duration = Duration::from_secs(2);

/// Cadence of the neutral gap detector.
pub const RESUME_WATCHDOG_INTERVAL: Duration = Duration::from_secs(5);

/// How far the wall clock must run ahead of the monotonic clock before we call
/// it a sleep. Comfortably above scheduler jitter and any sane NTP step, low
/// enough that a short lid-close is still caught.
pub const SLEEP_GAP_THRESHOLD: Duration = Duration::from_secs(45);

pub const TASK_ID_RESUME_WATCHDOG: &str = "resume-watchdog-tick";

/// Time that passed while this process was not running, or `None` when the two
/// clocks agree closely enough to be ordinary scheduling. `wall_delta` is
/// `None` when the system clock stepped backwards — an NTP correction, never a
/// wake.
pub fn detect_sleep_gap(
    wall_delta: Option<Duration>,
    mono_delta: Duration,
    threshold: Duration,
) -> Option<Duration> {
    let gap = wall_delta?.checked_sub(mono_delta)?;
    (gap >= threshold).then_some(gap)
}

/// Cross-cutting "re-resolve the binding now" request. Producers (the
/// fail-closed posture heartbeat) only set a flag; the watchdog task drains it
/// and runs the re-arm off every lock the producer might hold.
#[derive(Debug, Default)]
pub struct RebindRequests {
    pending: AtomicU64,
    reason: Mutex<Option<&'static str>>,
}

impl RebindRequests {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ask for a re-arm. Cheap and lock-light — safe from inside a compute.
    pub fn request(&self, reason: &'static str) {
        *self.reason.lock().unwrap_or_else(|p| p.into_inner()) = Some(reason);
        self.pending.fetch_add(1, Ordering::Release);
    }

    /// Take the pending request, if any, together with the reason last given.
    pub fn take(&self) -> Option<&'static str> {
        if self.pending.swap(0, Ordering::Acquire) == 0 {
            return None;
        }
        self.reason
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            .or(Some("rebind-requested"))
    }
}

/// Subscribes the platform power observer so a resume pokes the debounced
/// re-arm. Mirrors `NetworkChangeRearm`: the subscription is dropped before the
/// trigger (field order), so no callback fires into a stopped worker.
pub struct PowerResumeRearm {
    _subscription: PowerEventSubscription,
    _trigger: DebouncedTrigger,
}

impl PowerResumeRearm {
    pub fn start(
        observer: &dyn PowerEventObserver,
        rearm_hook: Arc<dyn Fn() + Send + Sync>,
        window: Duration,
    ) -> Result<Self, PlatformError> {
        let trigger = DebouncedTrigger::new(
            Arc::new(move || {
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    source = "power-event",
                    "machine resumed from sleep — re-resolving the adapter binding and re-driving routes",
                );
                rearm_hook();
            }),
            window,
        );
        let poke = trigger.poker();
        let subscription = observer.subscribe(Arc::new(move |event| {
            // Suspend is observed but not acted on: everything we could do is
            // undone by the sleep itself, and the wake path re-derives it all.
            if event == PowerEvent::Resume {
                poke();
            }
        }))?;
        Ok(Self {
            _subscription: subscription,
            _trigger: trigger,
        })
    }
}

/// Periodic gap detector plus [`RebindRequests`] drain. Runs on every platform,
/// including those with no power observer at all, and catches the wakes an OS
/// notification missed. `Optional`: a failure here costs promptness, never
/// enforcement.
pub fn build_resume_watchdog_task(
    requests: Arc<RebindRequests>,
    rearm_hook: Arc<dyn Fn() + Send + Sync>,
) -> ServiceTask {
    let mut last_mono = Instant::now();
    let mut last_wall = SystemTime::now();
    ServiceTask::periodic(
        TASK_ID_RESUME_WATCHDOG,
        TaskClass::Optional,
        RESUME_WATCHDOG_INTERVAL,
        RECOVERABLE_DEFAULT_MAX_RESTARTS,
        move |_stop| {
            let now_mono = Instant::now();
            let now_wall = SystemTime::now();
            let gap = detect_sleep_gap(
                now_wall.duration_since(last_wall).ok(),
                now_mono.duration_since(last_mono),
                SLEEP_GAP_THRESHOLD,
            );
            last_mono = now_mono;
            last_wall = now_wall;

            if let Some(gap) = gap {
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    source = "clock-gap",
                    slept_seconds = gap.as_secs(),
                    "machine resumed from sleep — re-resolving the adapter binding and re-driving routes",
                );
                rearm_hook();
                // The posture heartbeat's own request, if it raced in during the
                // sleep, is satisfied by the pass we just ran.
                let _ = requests.take();
                return TaskOutcome::Continue;
            }
            if let Some(reason) = requests.take() {
                tracing::info!(
                    target: "nrr::route-coordinator",
                    reason,
                    "re-resolving the adapter binding on request",
                );
                rearm_hook();
            }
            TaskOutcome::Continue
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::power::NoopPowerEventObserver;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn gap_detected_only_when_wall_runs_ahead_of_monotonic() {
        // Ordinary tick: both clocks advanced together.
        assert_eq!(
            detect_sleep_gap(
                Some(Duration::from_secs(5)),
                Duration::from_secs(5),
                SLEEP_GAP_THRESHOLD
            ),
            None
        );
        // Slept: 15 minutes of wall time, 5 s of monotonic time.
        assert_eq!(
            detect_sleep_gap(
                Some(Duration::from_secs(900)),
                Duration::from_secs(5),
                SLEEP_GAP_THRESHOLD
            ),
            Some(Duration::from_secs(895))
        );
        // A monotonic clock that ran LONGER than the wall clock (clock stepped
        // back mid-tick) is not a wake.
        assert_eq!(
            detect_sleep_gap(
                Some(Duration::from_secs(5)),
                Duration::from_secs(60),
                SLEEP_GAP_THRESHOLD
            ),
            None
        );
        // Backwards system clock: no wall delta at all.
        assert_eq!(
            detect_sleep_gap(None, Duration::from_secs(5), SLEEP_GAP_THRESHOLD),
            None
        );
        // Just under the threshold stays quiet (a busy scheduler, not a sleep).
        assert_eq!(
            detect_sleep_gap(
                Some(Duration::from_secs(44)),
                Duration::from_secs(5),
                Duration::from_secs(45)
            ),
            None
        );
    }

    #[test]
    fn rebind_request_is_taken_once() {
        let requests = RebindRequests::new();
        assert_eq!(requests.take(), None);
        requests.request("fail-closed-heartbeat");
        assert_eq!(requests.take(), Some("fail-closed-heartbeat"));
        assert_eq!(requests.take(), None);
    }

    #[test]
    fn resume_rearm_with_noop_observer_starts_and_stops_clean() {
        let fires = Arc::new(AtomicUsize::new(0));
        let f = Arc::clone(&fires);
        let rearm = PowerResumeRearm::start(
            &NoopPowerEventObserver,
            Arc::new(move || {
                f.fetch_add(1, Ordering::SeqCst);
            }),
            Duration::from_millis(50),
        )
        .expect("noop start never fails");
        std::thread::sleep(Duration::from_millis(120));
        assert_eq!(fires.load(Ordering::SeqCst), 0);
        drop(rearm);
    }
}
