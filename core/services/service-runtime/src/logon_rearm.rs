//! Sign-in re-arm for the local DNS resolver.
//!
//! Mode B intercepts DNS for the ACTIVE user's rules. Before anyone signs in
//! there is no SID, so there are no rules — the resolver would be a plain
//! forwarder, and an expensive one: arming it rewrites the machine-wide name
//! resolution policy, and doing that inside the logon phase leaves the OS
//! resolving names through a listener that is still coming up. Measured on this
//! product, that lands as tens of seconds of frozen logon screen.
//!
//! So the arm waits for a principal. The wait is event-driven — a sign-in is a
//! discrete thing the OS reports, and polling for it either arms into the middle
//! of the logon phase or minutes after the user is already working.
//!
//! The route path already gates on the same condition ("no routing user to
//! enforce"); this closes the gap that left DNS ungated. The same edges also
//! start a route pass, so a user who signs in without a tray is served at once.

use std::sync::Arc;
use std::time::Duration;

use nrr_platform_api::error::PlatformError;
use nrr_platform_api::logon_session::{
    LogonSessionEvent, LogonSessionObserver, LogonSessionSubscription,
};

use crate::network_rearm::DebouncedTrigger;

/// Coalescing window for sign-in signals. A logon emits several edges within a
/// moment (`SessionLogon` plus the console-connect that attaches it); one arm is
/// the correct answer to all of them. Kept short — the user is already waiting.
pub const LOGON_DEBOUNCE: Duration = Duration::from_millis(750);

/// How long after a sign-in the route pass runs. Longer than
/// [`LOGON_DEBOUNCE`]: the new session's token is issued a moment after the
/// logon edge, and a pass before it would not see the user. Without the pass a
/// user signed in with no tray waits for the periodic one, up to half a minute.
pub const LOGON_ROUTE_DEBOUNCE: Duration = Duration::from_secs(2);

/// How long after a sign-out the second route pass runs: past the departure
/// grace the first pass started, so the leaver's routes go now rather than on
/// the periodic pass.
pub const LOGOFF_ROUTE_DEBOUNCE: Duration = Duration::from_secs(
    LOGON_ROUTE_DEBOUNCE.as_secs() + crate::route_coordinator::DEPARTURE_GRACE.as_secs() + 1,
);

/// The route pass a sign-in or sign-out starts, beside the resolver re-arm.
pub struct LogonRoutePass {
    pub hook: Arc<dyn Fn() + Send + Sync>,
    pub arrival_window: Duration,
    pub departure_window: Duration,
}

/// Composes a [`LogonSessionObserver`] with a re-arm action: every sign-in pokes
/// a debounced trigger that re-applies the persisted enforcement mode, and, when
/// given one, the route pass. Holds the subscription and the triggers; drop
/// order (subscription first — see field order) cancels the OS registration
/// before the debounce threads stop, so no callback fires into a dead trigger.
pub struct LogonSessionRearm {
    // Rust drops fields top-to-bottom: cancel OS callbacks BEFORE the debounce
    // threads stop.
    _subscription: LogonSessionSubscription,
    _trigger: DebouncedTrigger,
    _route_triggers: Option<(DebouncedTrigger, DebouncedTrigger)>,
}

impl LogonSessionRearm {
    /// Subscribe `observer` so a sign-in debounces into `rearm`. Sign-OUT is
    /// deliberately not wired to it: tearing the resolver down is the route
    /// path's business, and doing it from two owners races.
    /// Returns `Err` if the OS registration fails — the caller keeps whatever
    /// periodic re-arm it already has.
    pub fn start(
        observer: &dyn LogonSessionObserver,
        rearm: Arc<dyn Fn() + Send + Sync>,
        window: Duration,
    ) -> Result<Self, PlatformError> {
        Self::start_with_routes(observer, rearm, window, None)
    }

    /// [`Self::start`], plus `routes`: a sign-in runs the route pass once its
    /// window passes, and a sign-out runs it twice — once to notice the leaver,
    /// once past the departure grace to drop them. One subscription for both:
    /// a platform may hold a single callback. The OS callback only pokes; every
    /// pass runs on a debounce thread.
    pub fn start_with_routes(
        observer: &dyn LogonSessionObserver,
        rearm: Arc<dyn Fn() + Send + Sync>,
        window: Duration,
        routes: Option<LogonRoutePass>,
    ) -> Result<Self, PlatformError> {
        let trigger = DebouncedTrigger::new(rearm, window);
        let poke = trigger.poker();
        let route_triggers = routes.map(|r| {
            (
                DebouncedTrigger::new(Arc::clone(&r.hook), r.arrival_window),
                DebouncedTrigger::new(r.hook, r.departure_window),
            )
        });
        let route_pokes = route_triggers
            .as_ref()
            .map(|(arrival, departure)| (arrival.poker(), departure.poker()));
        let subscription = observer.subscribe(Arc::new(move |event| match event {
            LogonSessionEvent::SignedIn => {
                poke();
                if let Some((arrival, _)) = route_pokes.as_ref() {
                    arrival();
                }
            }
            LogonSessionEvent::SignedOut => {
                if let Some((arrival, departure)) = route_pokes.as_ref() {
                    arrival();
                    departure();
                }
            }
        }))?;
        Ok(Self {
            _subscription: subscription,
            _trigger: trigger,
            _route_triggers: route_triggers,
        })
    }
}

/// Work that must not run before someone is signed in.
///
/// Same reasoning as the resolver arm above, one level wider: bringing up a
/// TUN adapter or flushing the OS resolver cache during the logon phase lands
/// machine-wide network churn inside the OS's own sign-in work, for a user
/// whose rules cannot apply yet. Each action runs exactly once — at once when
/// a user is already there (a service restart mid-session), else on the first
/// [`fire`](Self::fire).
pub struct SignInGate {
    signed_in: Arc<dyn Fn() -> bool + Send + Sync>,
    pending: std::sync::Mutex<Vec<DeferredStep>>,
}

/// A named action held back until sign-in.
type DeferredStep = (&'static str, Arc<dyn Fn() + Send + Sync>);

impl SignInGate {
    pub fn new(signed_in: Arc<dyn Fn() -> bool + Send + Sync>) -> Self {
        Self {
            signed_in,
            pending: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Run `action` now if a user is signed in, else hold it for `fire`.
    pub fn defer(&self, name: &'static str, action: Arc<dyn Fn() + Send + Sync>) {
        if (self.signed_in)() {
            action();
            return;
        }
        tracing::info!(target: "nrr::logon", msg_key = "logon-step-waiting", step = name, "waiting for a signed-in user");
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((name, action));
    }

    /// A user signed in: run everything held, once.
    pub fn fire(&self) {
        let held = std::mem::take(&mut *self.pending.lock().unwrap_or_else(|p| p.into_inner()));
        for (name, action) in held {
            tracing::info!(target: "nrr::logon", msg_key = "logon-step-running", step = name, "user signed in — running deferred step");
            action();
        }
    }

    /// [`Self::fire`] if a user is signed in now: for the moment the sign-in
    /// event source starts listening, after a sign-in it could not report.
    pub fn fire_if_signed_in(&self) {
        if (self.signed_in)() {
            self.fire();
        }
    }

    /// How many actions are still waiting.
    pub fn pending(&self) -> usize {
        self.pending.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// No sign-in event will come (no source, or it failed to subscribe): ask
    /// every `every` instead, and stop once the held steps have run — nothing
    /// polls a machine that is already past sign-in.
    pub fn poll_until_fired(gate: Arc<Self>, stop: crate::lifecycle::StopToken, every: Duration) {
        let spawned = std::thread::Builder::new()
            .name("nrr-sign-in-poll".into())
            .spawn(move || {
                while gate.pending() > 0 {
                    gate.fire_if_signed_in();
                    if gate.pending() == 0 || stop.wait_for(every) {
                        break;
                    }
                }
            });
        if let Err(e) = spawned {
            tracing::warn!(
                target: "nrr::logon",
                error = %e,
                "could not start the sign-in poll; held steps wait for the next sign-in event",
            );
        }
    }
}

/// How often the gate asks for a sign-in when no event will tell it.
pub const SIGN_IN_POLL_EVERY: Duration = Duration::from_secs(5);

#[cfg(test)]
mod gate_tests {
    use super::SignInGate;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    fn counting(runs: &Arc<AtomicUsize>) -> Arc<dyn Fn() + Send + Sync> {
        let runs = Arc::clone(runs);
        Arc::new(move || {
            runs.fetch_add(1, Ordering::SeqCst);
        })
    }

    #[test]
    fn before_sign_in_the_step_waits_and_then_runs_exactly_once() {
        let signed_in = Arc::new(AtomicBool::new(false));
        let gate = SignInGate::new({
            let s = Arc::clone(&signed_in);
            Arc::new(move || s.load(Ordering::SeqCst))
        });
        let runs = Arc::new(AtomicUsize::new(0));
        gate.defer("tun", counting(&runs));
        assert_eq!(runs.load(Ordering::SeqCst), 0, "nobody is signed in");
        assert_eq!(gate.pending(), 1);

        signed_in.store(true, Ordering::SeqCst);
        gate.fire();
        gate.fire();
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "a second sign-in must not repeat it"
        );
        assert_eq!(gate.pending(), 0);
    }

    /// A sign-in the event source started too late to see still releases
    /// what was held, and only once a user is really there.
    #[test]
    fn a_sign_in_before_the_source_listened_releases_the_held_steps() {
        let signed_in = Arc::new(AtomicBool::new(false));
        let gate = SignInGate::new({
            let s = Arc::clone(&signed_in);
            Arc::new(move || s.load(Ordering::SeqCst))
        });
        let runs = Arc::new(AtomicUsize::new(0));
        gate.defer("tun", counting(&runs));
        gate.fire_if_signed_in();
        assert_eq!(runs.load(Ordering::SeqCst), 0, "nobody is signed in");

        signed_in.store(true, Ordering::SeqCst);
        gate.fire_if_signed_in();
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    /// With no sign-in event to wait for, the poll releases the held step once
    /// a user is there, and then stops.
    #[test]
    fn without_a_sign_in_event_the_poll_releases_the_held_steps() {
        let signed_in = Arc::new(AtomicBool::new(false));
        let gate = Arc::new(SignInGate::new({
            let s = Arc::clone(&signed_in);
            Arc::new(move || s.load(Ordering::SeqCst))
        }));
        let runs = Arc::new(AtomicUsize::new(0));
        gate.defer("tun", counting(&runs));
        let stop = crate::lifecycle::StopToken::new();
        SignInGate::poll_until_fired(Arc::clone(&gate), stop.clone(), Duration::from_millis(5));
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(runs.load(Ordering::SeqCst), 0, "nobody is signed in");

        signed_in.store(true, Ordering::SeqCst);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while runs.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert_eq!(gate.pending(), 0);
        stop.request_stop();
    }

    #[test]
    fn with_a_user_already_there_the_step_runs_at_once() {
        let gate = SignInGate::new(Arc::new(|| true));
        let runs = Arc::new(AtomicUsize::new(0));
        gate.defer("flush", counting(&runs));
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert_eq!(gate.pending(), 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::logon_session::{LogonSessionCallback, LogonSessionSubscription};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// Observer that hands the parked callback back to the test.
    #[derive(Default)]
    struct FakeObserver(Mutex<Option<LogonSessionCallback>>);

    impl LogonSessionObserver for FakeObserver {
        fn subscribe(
            &self,
            on_event: LogonSessionCallback,
        ) -> Result<LogonSessionSubscription, PlatformError> {
            *self.0.lock().unwrap_or_else(|p| p.into_inner()) = Some(on_event);
            Ok(LogonSessionSubscription::inert())
        }
    }

    impl FakeObserver {
        fn fire(&self, event: LogonSessionEvent) {
            let cb = self
                .0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .as_ref()
                .map(Arc::clone);
            if let Some(cb) = cb {
                cb(event);
            }
        }
    }

    #[test]
    fn a_sign_in_rearms_and_a_sign_out_does_not() {
        let arms = Arc::new(AtomicUsize::new(0));
        let a = Arc::clone(&arms);
        let observer = FakeObserver::default();
        let rearm = LogonSessionRearm::start(
            &observer,
            Arc::new(move || {
                a.fetch_add(1, Ordering::SeqCst);
            }),
            Duration::from_millis(50),
        )
        .expect("fake subscribe never fails");

        observer.fire(LogonSessionEvent::SignedOut);
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(
            arms.load(Ordering::SeqCst),
            0,
            "a sign-out must not arm the resolver",
        );

        observer.fire(LogonSessionEvent::SignedIn);
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(arms.load(Ordering::SeqCst), 1);
        drop(rearm);
    }

    fn counting_hook(runs: &Arc<AtomicUsize>) -> Arc<dyn Fn() + Send + Sync> {
        let runs = Arc::clone(runs);
        Arc::new(move || {
            runs.fetch_add(1, Ordering::SeqCst);
        })
    }

    fn wait_for(runs: &AtomicUsize, at_least: usize) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while runs.load(Ordering::SeqCst) < at_least && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// A sign-in runs one route pass, off the OS callback, after the route
    /// window; the resolver re-arm still runs on its own.
    #[test]
    fn a_sign_in_runs_one_route_pass_after_its_window() {
        let arms = Arc::new(AtomicUsize::new(0));
        let passes = Arc::new(AtomicUsize::new(0));
        let observer = FakeObserver::default();
        let rearm = LogonSessionRearm::start_with_routes(
            &observer,
            counting_hook(&arms),
            Duration::from_millis(20),
            Some(LogonRoutePass {
                hook: counting_hook(&passes),
                arrival_window: Duration::from_millis(150),
                departure_window: Duration::from_millis(400),
            }),
        )
        .expect("fake subscribe never fails");

        observer.fire(LogonSessionEvent::SignedIn);
        assert_eq!(
            passes.load(Ordering::SeqCst),
            0,
            "the OS callback only pokes; the pass waits for its window"
        );
        wait_for(&passes, 1);
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(passes.load(Ordering::SeqCst), 1, "one sign-in, one pass");
        assert_eq!(arms.load(Ordering::SeqCst), 1);
        drop(rearm);
    }

    /// A sign-out runs the pass that notices the leaver and the one past the
    /// departure grace; the resolver is not re-armed by it.
    #[test]
    fn a_sign_out_runs_a_pass_and_another_past_the_grace() {
        let arms = Arc::new(AtomicUsize::new(0));
        let passes = Arc::new(AtomicUsize::new(0));
        let observer = FakeObserver::default();
        let rearm = LogonSessionRearm::start_with_routes(
            &observer,
            counting_hook(&arms),
            Duration::from_millis(20),
            Some(LogonRoutePass {
                hook: counting_hook(&passes),
                arrival_window: Duration::from_millis(50),
                departure_window: Duration::from_millis(300),
            }),
        )
        .expect("fake subscribe never fails");

        observer.fire(LogonSessionEvent::SignedOut);
        wait_for(&passes, 1);
        assert_eq!(passes.load(Ordering::SeqCst), 1, "the departure pass waits");
        wait_for(&passes, 2);
        assert_eq!(passes.load(Ordering::SeqCst), 2);
        assert_eq!(arms.load(Ordering::SeqCst), 0);
        drop(rearm);
    }

    #[test]
    fn the_logon_edge_burst_collapses_into_one_arm() {
        let arms = Arc::new(AtomicUsize::new(0));
        let a = Arc::clone(&arms);
        let observer = FakeObserver::default();
        let rearm = LogonSessionRearm::start(
            &observer,
            Arc::new(move || {
                a.fetch_add(1, Ordering::SeqCst);
            }),
            Duration::from_millis(100),
        )
        .expect("fake subscribe never fails");

        // SessionLogon + ConsoleConnect + a remote edge, as one sign-in produces.
        for _ in 0..3 {
            observer.fire(LogonSessionEvent::SignedIn);
        }
        std::thread::sleep(Duration::from_millis(300));
        let n = arms.load(Ordering::SeqCst);
        assert!(
            (1..=2).contains(&n),
            "one sign-in must arm once (allow 2 for a straddled window), got {n}",
        );
        drop(rearm);
    }
}
