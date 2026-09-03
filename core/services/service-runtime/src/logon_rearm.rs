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
//! enforce"); this closes the gap that left DNS ungated.

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

/// Composes a [`LogonSessionObserver`] with a re-arm action: every sign-in pokes
/// a debounced trigger that re-applies the persisted enforcement mode. Holds
/// both the subscription and the trigger; drop order (subscription first — see
/// field order) cancels the OS registration before the debounce thread stops, so
/// no callback fires into a dead trigger.
pub struct LogonSessionRearm {
    // Rust drops fields top-to-bottom: cancel OS callbacks BEFORE the debounce
    // thread stops.
    _subscription: LogonSessionSubscription,
    _trigger: DebouncedTrigger,
}

impl LogonSessionRearm {
    /// Subscribe `observer` so a sign-in debounces into `rearm`. Sign-OUT is
    /// deliberately not wired here: tearing the resolver down is the route
    /// path's business, and doing it from two owners races.
    /// Returns `Err` if the OS registration fails — the caller keeps whatever
    /// periodic re-arm it already has.
    pub fn start(
        observer: &dyn LogonSessionObserver,
        rearm: Arc<dyn Fn() + Send + Sync>,
        window: Duration,
    ) -> Result<Self, PlatformError> {
        let trigger = DebouncedTrigger::new(rearm, window);
        let poke = trigger.poker();
        let subscription = observer.subscribe(Arc::new(move |event| {
            if event == LogonSessionEvent::SignedIn {
                poke();
            }
        }))?;
        Ok(Self {
            _subscription: subscription,
            _trigger: trigger,
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
        tracing::info!(target: "nrr::logon", step = name, "waiting for a signed-in user");
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((name, action));
    }

    /// A user signed in: run everything held, once.
    pub fn fire(&self) {
        let held = std::mem::take(&mut *self.pending.lock().unwrap_or_else(|p| p.into_inner()));
        for (name, action) in held {
            tracing::info!(target: "nrr::logon", step = name, "user signed in — running deferred step");
            action();
        }
    }

    /// How many actions are still waiting.
    pub fn pending(&self) -> usize {
        self.pending.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

#[cfg(test)]
mod gate_tests {
    use super::SignInGate;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

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
