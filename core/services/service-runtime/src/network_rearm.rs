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

use crate::service_tasks::ServiceTaskKind;
use crate::task_liveness::{TaskLiveness, ThreadExit, ThreadLease, Watch};

/// A fire still running past this is a hang of the pass behind it.
const FIRE_DEADLINE: Duration = Duration::from_secs(120);

/// Coalescing window: bursts of OS change callbacks within this window collapse
/// into a single re-arm. 500 ms matches the adapter-monitor debounce and smooths
/// Wi-Fi-roam / VPN-reconnect flaps without adding perceptible re-arm latency.
pub const NETWORK_CHANGE_DEBOUNCE: Duration = Duration::from_millis(500);

/// Longest pause, in windows from the first poke: a change stream that never
/// goes quiet is acted on at this pace.
pub const MAX_PAUSE_IN_WINDOWS: u32 = 4;

struct DebounceState {
    pending: bool,
    stop: bool,
    /// Pokes since the last fire, for the debug line that tunes the cap.
    pokes: u32,
}

struct DebounceInner {
    state: Mutex<DebounceState>,
    cv: Condvar,
    target: Arc<dyn Fn() + Send + Sync>,
    window: Duration,
    label: &'static str,
}

impl DebounceInner {
    fn lock(&self) -> std::sync::MutexGuard<'_, DebounceState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// Owns a worker thread that coalesces `poke()`s into calls to `target`. A poke
/// arms a fire that happens once the pokes have been quiet for the window, or
/// [`MAX_PAUSE_IN_WINDOWS`] windows after the first. Dropping stops and joins
/// the thread.
pub struct DebouncedTrigger {
    inner: Arc<DebounceInner>,
    join: Option<JoinHandle<()>>,
}

impl DebouncedTrigger {
    /// Spawn the coalescing worker. `target` is invoked (off the poking thread)
    /// once per burst of pokes, `window` after the last.
    pub fn new(target: Arc<dyn Fn() + Send + Sync>, window: Duration) -> Self {
        Self::new_observed(target, window, None)
    }

    /// [`Self::new`], with the worker holding a liveness lease under `label`.
    pub fn new_observed(
        target: Arc<dyn Fn() + Send + Sync>,
        window: Duration,
        observed: Option<(Arc<TaskLiveness>, &'static str)>,
    ) -> Self {
        let inner = Arc::new(DebounceInner {
            state: Mutex::new(DebounceState {
                pending: false,
                stop: false,
                pokes: 0,
            }),
            cv: Condvar::new(),
            target,
            window,
            label: observed.as_ref().map_or("unlabelled", |(_, label)| *label),
        });
        let worker = Arc::clone(&inner);
        let join = std::thread::Builder::new()
            .name("nrr-net-change-debounce".to_string())
            .spawn(move || {
                let lease = observed.map(|(liveness, label)| {
                    liveness.lease(
                        ServiceTaskKind::NetChangeDebounce,
                        Some(label),
                        Watch::Work(FIRE_DEADLINE),
                    )
                });
                Self::run(worker, lease.as_ref());
                if let Some(lease) = lease {
                    lease.finish(ThreadExit::Stopped);
                }
            })
            .ok();
        Self { inner, join }
    }

    fn run(inner: Arc<DebounceInner>, lease: Option<&ThreadLease>) {
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
            // Fire once the burst has been quiet for a window, so the pass
            // sees the network settled; a burst that never goes quiet fires
            // at the cap. A poke during the wait joins this burst; one during
            // the fire starts the next.
            let first = Instant::now();
            let cap = first + inner.window * MAX_PAUSE_IN_WINDOWS;
            let mut quiet_from = first;
            let events = {
                let mut st = inner.lock();
                loop {
                    if st.stop {
                        return;
                    }
                    let now = Instant::now();
                    if std::mem::take(&mut st.pending) {
                        quiet_from = now;
                    }
                    let deadline = (quiet_from + inner.window).min(cap);
                    if now >= deadline {
                        break std::mem::take(&mut st.pokes);
                    }
                    let (guard, _timeout) = inner
                        .cv
                        .wait_timeout(st, deadline - now)
                        .unwrap_or_else(|p| p.into_inner());
                    st = guard;
                }
            };
            // How long bursts run on real machines, to tune the cap by.
            tracing::debug!(
                target: "nrr::route-coordinator",
                trigger = inner.label,
                events,
                waited_ms = u64::try_from(first.elapsed().as_millis()).unwrap_or(u64::MAX),
                capped = Instant::now() >= cap,
                "change burst settled",
            );
            let _fire = lease.map(ThreadLease::work);
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
                st.pokes = st.pokes.saturating_add(1);
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
        Self::start_observed(observer, recompute_hook, window, None)
    }

    /// [`Self::start`], with the debounce worker reporting to `liveness`.
    pub fn start_observed(
        observer: &dyn NetworkChangeObserver,
        recompute_hook: Arc<dyn Fn() + Send + Sync>,
        window: Duration,
        liveness: Option<Arc<TaskLiveness>>,
    ) -> Result<Self, PlatformError> {
        let trigger = DebouncedTrigger::new_observed(
            recompute_hook,
            window,
            liveness.map(|liveness| (liveness, "network")),
        );
        // Our own route writes would otherwise start the pause after every
        // pass that writes, and hold a real change behind them.
        let subscription = observer.subscribe_foreign(trigger.poker())?;
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
        // Regression guard: pokes spread across time (a VPN reconnect emits
        // interface/route callbacks tens of ms apart) must still collapse to
        // ~once-per-window, NOT once-per-poke. A per-poke bug fires ~10× here;
        // correct fixed-window coalescing fires ~2–3×.
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

    fn counting_trigger(window: Duration) -> (Arc<AtomicUsize>, DebouncedTrigger) {
        let fires = Arc::new(AtomicUsize::new(0));
        let f = Arc::clone(&fires);
        let trigger = DebouncedTrigger::new(
            Arc::new(move || {
                f.fetch_add(1, Ordering::SeqCst);
            }),
            window,
        );
        (fires, trigger)
    }

    /// A tunnel coming up reports its changes over a second or so; a pass
    /// started in the middle judges a half-built network and runs again.
    /// The pause counts from the last change.
    #[test]
    fn the_pause_runs_from_the_last_change_not_the_first() {
        let (fires, trigger) = counting_trigger(Duration::from_millis(400));
        let poke = trigger.poker();
        poke();
        std::thread::sleep(Duration::from_millis(300));
        poke();
        std::thread::sleep(Duration::from_millis(250));
        assert_eq!(
            fires.load(Ordering::SeqCst),
            0,
            "the pass ran while the network was still changing"
        );
        std::thread::sleep(Duration::from_millis(550));
        assert_eq!(fires.load(Ordering::SeqCst), 1);
        drop(trigger);
    }

    /// A link that never stops flapping still gets its pass: quiet that never
    /// comes does not hold it back for good.
    #[test]
    fn a_change_stream_without_quiet_still_fires() {
        let window = Duration::from_millis(200);
        let (fires, trigger) = counting_trigger(window);
        let poke = trigger.poker();
        let until = Instant::now() + window * (MAX_PAUSE_IN_WINDOWS + 2);
        while Instant::now() < until {
            poke();
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            fires.load(Ordering::SeqCst) >= 1,
            "a steady stream of changes was never acted on"
        );
        drop(trigger);
    }

    /// The notices of our own route writes leave the pause alone: the
    /// re-arm subscribes to the changes made by others only.
    #[test]
    fn the_rearm_does_not_listen_to_our_own_route_writes() {
        #[derive(Default)]
        struct Recording {
            foreign: std::sync::atomic::AtomicBool,
        }
        impl NetworkChangeObserver for Recording {
            fn subscribe(
                &self,
                _on_change: NetworkChangeCallback,
            ) -> Result<NetworkChangeSubscription, PlatformError> {
                Ok(NetworkChangeSubscription::inert())
            }
            fn subscribe_foreign(
                &self,
                _on_change: NetworkChangeCallback,
            ) -> Result<NetworkChangeSubscription, PlatformError> {
                self.foreign.store(true, Ordering::SeqCst);
                Ok(NetworkChangeSubscription::inert())
            }
        }
        let observer = Recording::default();
        let rearm =
            NetworkChangeRearm::start(&observer, Arc::new(|| {}), Duration::from_millis(50))
                .expect("subscribes");
        assert!(observer.foreign.load(Ordering::SeqCst));
        drop(rearm);
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
