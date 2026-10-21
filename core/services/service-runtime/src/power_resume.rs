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

/// How close in BOTH clocks two resume signals must be to be the same wake.
/// The OS notification and the gap detector see one wake seconds apart; a
/// sleep between two signals moves the wall clock past this.
pub const RESUME_DEDUP_WINDOW: Duration = Duration::from_secs(30);

/// Whether a resume seen now is the wake already claimed at `prev`. A wall
/// clock stepped backwards is a correction, not a sleep, so only the
/// monotonic distance decides then.
pub fn is_same_wake(
    prev: (Instant, SystemTime),
    now: (Instant, SystemTime),
    window: Duration,
) -> bool {
    let mono_close = now.0.saturating_duration_since(prev.0) < window;
    let wall_close = now.1.duration_since(prev.1).ok().is_none_or(|d| d < window);
    mono_close && wall_close
}

/// One wake, one re-arm: the first resume source to report a wake claims it,
/// and the other one stands down for that wake.
#[derive(Debug, Default)]
pub struct WakeLatch {
    claimed: Mutex<Option<(Instant, SystemTime)>>,
}

impl WakeLatch {
    /// `true` when nobody has re-armed for this wake yet.
    pub fn claim(&self) -> bool {
        self.claim_at((Instant::now(), SystemTime::now()))
    }

    fn claim_at(&self, now: (Instant, SystemTime)) -> bool {
        let mut claimed = self.claimed.lock().unwrap_or_else(|p| p.into_inner());
        if claimed.is_some_and(|prev| is_same_wake(prev, now, RESUME_DEDUP_WINDOW)) {
            return false;
        }
        *claimed = Some(now);
        true
    }

    /// The machine is going to sleep: whatever wakes it next is a new wake,
    /// however soon.
    pub fn forget(&self) {
        *self.claimed.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }
}

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
    wake: WakeLatch,
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

    /// Shared by both resume sources, which already share this value.
    pub fn wake_latch(&self) -> &WakeLatch {
        &self.wake
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
        Self::start_observed(observer, rearm_hook, window, None)
    }

    /// [`Self::start`], with the debounce worker reporting to `liveness`.
    pub fn start_observed(
        observer: &dyn PowerEventObserver,
        rearm_hook: Arc<dyn Fn() + Send + Sync>,
        window: Duration,
        liveness: Option<Arc<crate::task_liveness::TaskLiveness>>,
    ) -> Result<Self, PlatformError> {
        Self::start_deduped(observer, rearm_hook, window, liveness, None)
    }

    /// [`Self::start_observed`], standing down for a wake the resume watchdog
    /// sharing `requests` has already re-armed for.
    pub fn start_deduped(
        observer: &dyn PowerEventObserver,
        rearm_hook: Arc<dyn Fn() + Send + Sync>,
        window: Duration,
        liveness: Option<Arc<crate::task_liveness::TaskLiveness>>,
        requests: Option<Arc<RebindRequests>>,
    ) -> Result<Self, PlatformError> {
        let fire_requests = requests.clone();
        let trigger = DebouncedTrigger::new_observed(
            Arc::new(move || {
                if fire_requests
                    .as_ref()
                    .is_some_and(|r| !r.wake_latch().claim())
                {
                    tracing::debug!(
                        target: "nrr::route-coordinator",
                        "resume already re-armed for by the clock-gap watchdog",
                    );
                    return;
                }
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    msg_key = "power-resume-from-sleep",
                    source = "power-event",
                    "machine resumed from sleep — re-resolving the adapter binding and re-driving routes",
                );
                rearm_hook();
            }),
            window,
            liveness.map(|liveness| (liveness, "power")),
        );
        let poke = trigger.poker();
        let subscription = observer.subscribe(Arc::new(move |event| match event {
            PowerEvent::Resume => poke(),
            // Nothing is acted on before a sleep: the sleep undoes it, and the
            // wake re-derives it all. The next resume is a new wake.
            PowerEvent::Suspend => {
                if let Some(requests) = requests.as_ref() {
                    requests.wake_latch().forget();
                }
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
            watchdog_tick(gap, &requests, rearm_hook.as_ref());
            TaskOutcome::Continue
        },
    )
}

/// One watchdog pass, given the sleep gap it measured.
fn watchdog_tick(gap: Option<Duration>, requests: &RebindRequests, rearm_hook: &dyn Fn()) {
    if let Some(gap) = gap {
        if requests.wake_latch().claim() {
            tracing::warn!(
                target: "nrr::route-coordinator",
                msg_key = "power-resume-from-sleep",
                source = "clock-gap",
                slept_seconds = gap.as_secs(),
                "machine resumed from sleep — re-resolving the adapter binding and re-driving routes",
            );
            rearm_hook();
        }
        // The pass for this wake also answers a request the posture heartbeat
        // raised during the sleep.
        let _ = requests.take();
        return;
    }
    if let Some(reason) = requests.take() {
        tracing::info!(
            target: "nrr::route-coordinator",
            msg_key = "power-resume-rebind-requested",
            reason,
            "re-resolving the adapter binding on request",
        );
        rearm_hook();
    }
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

    /// An observer the test drives by hand, as the OS would.
    #[derive(Default)]
    struct ManualPowerObserver {
        callback: Mutex<Option<nrr_platform_api::power::PowerEventCallback>>,
    }

    impl ManualPowerObserver {
        fn emit(&self, event: PowerEvent) {
            let callback = self.callback.lock().expect("lock").clone();
            if let Some(callback) = callback {
                callback(event);
            }
        }
    }

    impl PowerEventObserver for ManualPowerObserver {
        fn subscribe(
            &self,
            on_event: nrr_platform_api::power::PowerEventCallback,
        ) -> Result<PowerEventSubscription, PlatformError> {
            *self.callback.lock().expect("lock") = Some(on_event);
            Ok(PowerEventSubscription::inert())
        }
    }

    const SLEPT: Option<Duration> = Some(Duration::from_secs(900));
    const SETTLE: Duration = Duration::from_millis(250);

    fn counting_hook() -> (Arc<AtomicUsize>, Arc<dyn Fn() + Send + Sync>) {
        let fires = Arc::new(AtomicUsize::new(0));
        let f = Arc::clone(&fires);
        let hook: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            f.fetch_add(1, Ordering::SeqCst);
        });
        (fires, hook)
    }

    #[test]
    fn a_wake_reported_first_by_the_os_is_not_rearmed_again_by_the_clock_gap() {
        let (fires, hook) = counting_hook();
        let requests = Arc::new(RebindRequests::new());
        let observer = ManualPowerObserver::default();
        let _rearm = PowerResumeRearm::start_deduped(
            &observer,
            Arc::clone(&hook),
            Duration::from_millis(50),
            None,
            Some(Arc::clone(&requests)),
        )
        .expect("manual observer subscribes");

        observer.emit(PowerEvent::Resume);
        std::thread::sleep(SETTLE);
        assert_eq!(fires.load(Ordering::SeqCst), 1);

        watchdog_tick(SLEPT, &requests, hook.as_ref());
        assert_eq!(fires.load(Ordering::SeqCst), 1, "same wake, one re-arm");

        // The next sleep is announced, so its wake re-arms however soon it is.
        observer.emit(PowerEvent::Suspend);
        observer.emit(PowerEvent::Resume);
        std::thread::sleep(SETTLE);
        assert_eq!(fires.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_wake_caught_first_by_the_clock_gap_is_not_rearmed_again_by_the_os() {
        let (fires, hook) = counting_hook();
        let requests = Arc::new(RebindRequests::new());
        let observer = ManualPowerObserver::default();
        let _rearm = PowerResumeRearm::start_deduped(
            &observer,
            Arc::clone(&hook),
            Duration::from_millis(50),
            None,
            Some(Arc::clone(&requests)),
        )
        .expect("manual observer subscribes");

        watchdog_tick(SLEPT, &requests, hook.as_ref());
        assert_eq!(fires.load(Ordering::SeqCst), 1);
        observer.emit(PowerEvent::Resume);
        std::thread::sleep(SETTLE);
        assert_eq!(fires.load(Ordering::SeqCst), 1, "same wake, one re-arm");
    }

    #[test]
    fn the_watchdog_alone_rearms_on_a_gap_and_on_a_request() {
        let (fires, hook) = counting_hook();
        let requests = RebindRequests::new();
        watchdog_tick(None, &requests, hook.as_ref());
        assert_eq!(fires.load(Ordering::SeqCst), 0);
        requests.request("fail-closed-heartbeat");
        watchdog_tick(None, &requests, hook.as_ref());
        assert_eq!(fires.load(Ordering::SeqCst), 1);
        // A request raised during the sleep is answered by the wake's pass.
        requests.request("fail-closed-heartbeat");
        watchdog_tick(SLEPT, &requests, hook.as_ref());
        assert_eq!(fires.load(Ordering::SeqCst), 2);
        assert_eq!(requests.take(), None);
    }

    #[test]
    fn two_signals_are_one_wake_only_when_both_clocks_stayed_close() {
        let mono = Instant::now();
        let wall = SystemTime::now();
        let w = RESUME_DEDUP_WINDOW;
        let soon = Duration::from_secs(3);
        assert!(is_same_wake((mono, wall), (mono + soon, wall + soon), w));
        // A sleep between them: the wall clock ran on, the monotonic did not.
        assert!(!is_same_wake(
            (mono, wall),
            (mono + soon, wall + Duration::from_secs(600)),
            w
        ));
        assert!(!is_same_wake((mono, wall), (mono + w, wall + w), w));
        // A wall clock stepped back is a correction; monotonic time decides.
        assert!(is_same_wake((mono, wall + soon), (mono + soon, wall), w));
    }

    #[test]
    fn a_claimed_wake_is_claimed_once_until_forgotten() {
        let latch = WakeLatch::default();
        let now = (Instant::now(), SystemTime::now());
        assert!(latch.claim_at(now));
        assert!(!latch.claim_at(now));
        latch.forget();
        assert!(latch.claim_at(now));
    }
}
