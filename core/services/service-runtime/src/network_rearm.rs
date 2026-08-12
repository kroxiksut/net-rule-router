//! Debounced network-change re-arm.
//!
//! Bridges the platform [`NetworkChangeObserver`] to the existing
//! `route_recompute_hook`: an OS interface/route change re-drives routing +
//! kill-switch IMMEDIATELY instead of waiting for the 1 s adapter poll or the
//! 30 s safety tick. The observer's raw callback fires once per OS change (and
//! a flapping link produces bursts), so the coalescing lives HERE, in neutral,
//! unit-testable code — the platform impl stays a thin FFI shim.
//!
//! The polling fallbacks (1 s adapter monitor, 30 s route-reconcile safety) are
//! intentionally NOT removed: OS notifications are missed across sleep/resume,
//! so the ticks remain the belt-and-suspenders.

use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use nrr_platform_api::error::PlatformError;
use nrr_platform_api::network_change::{NetworkChangeObserver, NetworkChangeSubscription};

/// Coalescing window: bursts of OS change callbacks within this window collapse
/// into a single re-arm. 500 ms matches the adapter-monitor debounce and smooths
/// Wi-Fi-roam / VPN-reconnect flaps without adding perceptible re-arm latency.
pub const NETWORK_CHANGE_DEBOUNCE: Duration = Duration::from_millis(500);

struct DebounceState {
    pending: bool,
    stop: bool,
}

struct DebounceInner {
    state: Mutex<DebounceState>,
    cv: Condvar,
    target: Arc<dyn Fn() + Send + Sync>,
    window: Duration,
}

impl DebounceInner {
    fn lock(&self) -> std::sync::MutexGuard<'_, DebounceState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// Owns a worker thread that coalesces `poke()`s into calls to `target`. A poke
/// arms a fire that happens after the window; further pokes during the wait are
/// coalesced into the same (or the next) fire. Dropping stops and joins the
/// thread.
pub struct DebouncedTrigger {
    inner: Arc<DebounceInner>,
    join: Option<JoinHandle<()>>,
}

impl DebouncedTrigger {
    /// Spawn the coalescing worker. `target` is invoked (off the poking thread)
    /// at most once per `window` after a burst of pokes.
    pub fn new(target: Arc<dyn Fn() + Send + Sync>, window: Duration) -> Self {
        let inner = Arc::new(DebounceInner {
            state: Mutex::new(DebounceState {
                pending: false,
                stop: false,
            }),
            cv: Condvar::new(),
            target,
            window,
        });
        let worker = Arc::clone(&inner);
        let join = std::thread::Builder::new()
            .name("nrr-net-change-debounce".to_string())
            .spawn(move || Self::run(worker))
            .ok();
        Self { inner, join }
    }

    fn run(inner: Arc<DebounceInner>) {
        loop {
            // Wait for the first poke of a burst (or stop).
            {
                let mut st = inner.lock();
                while !st.pending && !st.stop {
                    st = inner.cv.wait(st).unwrap_or_else(|p| p.into_inner());
                }
                if st.stop {
                    return;
                }
                st.pending = false;
            }
            // Coalesce the burst over a FIXED window measured from the first
            // poke. `poker()` and `Drop` share this Condvar, so a naive single
            // `wait_timeout(window)` would be cut short by every intervening
            // poke — firing ~once per poke instead of once per window during a
            // sustained flap (VPN reconnect / Wi-Fi roam emit pokes tens of ms
            // apart). Loop against an absolute deadline so poke wake-ups are
            // ignored; only `stop` cuts it short. Pokes during the window set
            // `pending` again and fire on the NEXT iteration (trailing flush).
            let deadline = Instant::now() + inner.window;
            {
                let mut st = inner.lock();
                loop {
                    if st.stop {
                        return;
                    }
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    let (guard, _timeout) = inner
                        .cv
                        .wait_timeout(st, deadline - now)
                        .unwrap_or_else(|p| p.into_inner());
                    st = guard;
                }
            }
            (inner.target)();
        }
    }

    /// A cheap, thread-safe closure that arms a fire. Safe to call from an OS
    /// callback thread — it only locks briefly and notifies.
    pub fn poker(&self) -> Arc<dyn Fn() + Send + Sync> {
        let inner = Arc::clone(&self.inner);
        Arc::new(move || {
            {
                let mut st = inner.lock();
                st.pending = true;
            }
            inner.cv.notify_all();
        })
    }
}

impl Drop for DebouncedTrigger {
    fn drop(&mut self) {
        {
            let mut st = self.inner.lock();
            st.stop = true;
        }
        self.inner.cv.notify_all();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Composes a [`NetworkChangeObserver`] with the recompute hook: subscribes the
/// observer so every OS change pokes the debounced trigger, which re-drives the
/// route table + kill-switch. Holds both the subscription and the trigger; drop
/// order (subscription first — see field order) cancels the OS notification
/// before the debounce thread stops, so no callback fires into a dead trigger.
pub struct NetworkChangeRearm {
    // Rust drops fields top-to-bottom: cancel OS callbacks BEFORE the debounce
    // thread stops.
    _subscription: NetworkChangeSubscription,
    _trigger: DebouncedTrigger,
}

impl NetworkChangeRearm {
    /// Subscribe `observer` so OS network changes debounce into `recompute_hook`.
    /// Returns `Err` if the OS registration fails — the caller keeps the polling
    /// fallback.
    pub fn start(
        observer: &dyn NetworkChangeObserver,
        recompute_hook: Arc<dyn Fn() + Send + Sync>,
        window: Duration,
    ) -> Result<Self, PlatformError> {
        let trigger = DebouncedTrigger::new(recompute_hook, window);
        let subscription = observer.subscribe(trigger.poker())?;
        Ok(Self {
            _subscription: subscription,
            _trigger: trigger,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::network_change::{NetworkChangeCallback, NoopNetworkChangeObserver};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn burst_of_pokes_coalesces_into_at_most_one_fire_per_window() {
        let fires = Arc::new(AtomicUsize::new(0));
        let f = Arc::clone(&fires);
        let trigger = DebouncedTrigger::new(
            Arc::new(move || {
                f.fetch_add(1, Ordering::SeqCst);
            }),
            Duration::from_millis(100),
        );
        let poke = trigger.poker();
        // Rapid burst — must collapse.
        for _ in 0..20 {
            poke();
        }
        // Let the window elapse + margin.
        std::thread::sleep(Duration::from_millis(300));
        let n = fires.load(Ordering::SeqCst);
        assert!(
            (1..=2).contains(&n),
            "a 20-poke burst should fire once (allow 2 for a straddled window), got {n}",
        );
        drop(trigger);
    }

    #[test]
    fn spread_out_pokes_coalesce_instead_of_firing_per_poke() {
        // Regression (F7 Track 2 adversarial review): pokes spread across time
        // (a VPN reconnect emits interface/route callbacks tens of ms apart)
        // must still collapse to ~once-per-window, NOT once-per-poke. A per-poke
        // bug fires ~10× here; correct fixed-window coalescing fires ~2–3×.
        let fires = Arc::new(AtomicUsize::new(0));
        let f = Arc::clone(&fires);
        let trigger = DebouncedTrigger::new(
            Arc::new(move || {
                f.fetch_add(1, Ordering::SeqCst);
            }),
            Duration::from_millis(200),
        );
        let poke = trigger.poker();
        // 10 pokes, 40 ms apart ≈ 400 ms of flapping under a 200 ms window.
        for _ in 0..10 {
            poke();
            std::thread::sleep(Duration::from_millis(40));
        }
        std::thread::sleep(Duration::from_millis(400));
        let n = fires.load(Ordering::SeqCst);
        assert!(
            (1..=4).contains(&n),
            "spread pokes must coalesce to a few fires (not ~10 per-poke), got {n}",
        );
        drop(trigger);
    }

    #[test]
    fn no_poke_never_fires() {
        let fires = Arc::new(AtomicUsize::new(0));
        let f = Arc::clone(&fires);
        let trigger = DebouncedTrigger::new(
            Arc::new(move || {
                f.fetch_add(1, Ordering::SeqCst);
            }),
            Duration::from_millis(50),
        );
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(fires.load(Ordering::SeqCst), 0);
        drop(trigger);
    }

    #[test]
    fn drop_stops_the_worker_promptly() {
        // A trigger with a long window must still drop quickly (stop wakes the
        // wait) rather than blocking for the full window.
        let trigger = DebouncedTrigger::new(Arc::new(|| {}), Duration::from_secs(30));
        trigger.poker()(); // arm a fire so the worker is inside the window wait
        std::thread::sleep(Duration::from_millis(20));
        let t0 = std::time::Instant::now();
        drop(trigger);
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "drop must interrupt the window wait, took {:?}",
            t0.elapsed()
        );
    }

    #[test]
    fn rearm_with_noop_observer_starts_and_stops_clean() {
        let fires = Arc::new(AtomicUsize::new(0));
        let f = Arc::clone(&fires);
        let hook: NetworkChangeCallback = Arc::new(move || {
            f.fetch_add(1, Ordering::SeqCst);
        });
        let observer = NoopNetworkChangeObserver;
        let rearm = NetworkChangeRearm::start(&observer, hook, Duration::from_millis(50))
            .expect("noop start never fails");
        // Noop observer never fires, so the hook is never called.
        std::thread::sleep(Duration::from_millis(120));
        assert_eq!(fires.load(Ordering::SeqCst), 0);
        drop(rearm);
    }
}
