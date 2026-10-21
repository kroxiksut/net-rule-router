//! A pass asked for by what was learnt, gathered into one.
//!
//! The observation ticks (DNS, connections, programs, the refresh) each ask for
//! a pass when they learn an address. Browsing learns one every second or two,
//! and a pass costs seconds of one core, so a pass per address is a core busy
//! for as long as the page keeps loading. These requests tolerate a short delay
//! -- the address is routed a moment later, as it was when the pass ran behind
//! the previous one -- so they are collected for a window and answered by one.
//! Callers that must see their facts enforced before they go on (the resolver's
//! answer gate, the seed) keep the plain, synchronous hook.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::supervised_runtime::RouteRecomputeHook;

/// How long learnt addresses are gathered while nothing is blocked. Short
/// enough that an address is routed before its page has finished loading,
/// long enough that a pass of a couple of seconds covers a burst of them.
pub const OBSERVATION_PASS_WINDOW: Duration = Duration::from_secs(2);

/// The window for the posture: none while a leak guard blocks, because an
/// address learnt then is dropped, not merely routed late, until its pass ran.
#[must_use]
pub fn window_for(blocking: bool) -> Duration {
    if blocking {
        Duration::ZERO
    } else {
        OBSERVATION_PASS_WINDOW
    }
}

/// How long to gather at this moment.
pub type WindowFn = Arc<dyn Fn() -> Duration + Send + Sync>;

/// Whether the service is stopping: a gathered pass must not start then.
pub type StopFn = Arc<dyn Fn() -> bool + Send + Sync>;

/// How often the worker re-reads the window and the stop flag while waiting.
const SLICE: Duration = Duration::from_millis(100);

struct Gather {
    inner: RouteRecomputeHook,
    window: WindowFn,
    stopping: StopFn,
    /// Asked for since the worker last started a pass.
    pending: AtomicBool,
    /// A worker is waiting out a window or running a pass.
    running: AtomicBool,
}

/// Clears `running` however the worker ends, a panic included: left set, no
/// later request would ever start a worker again.
struct WorkerDone(Arc<Gather>);

impl Drop for WorkerDone {
    fn drop(&mut self) {
        self.0.running.store(false, Ordering::SeqCst);
        // A request that landed between the last check and the clear.
        if self.0.pending.load(Ordering::SeqCst) {
            start_worker(&self.0);
        }
    }
}

/// Waits in slices so a window that drops to zero (a guard armed meanwhile)
/// ends the wait at once. `false` when the service began stopping.
fn wait_out_window(gather: &Gather) -> bool {
    let began = Instant::now();
    loop {
        if (gather.stopping)() {
            return false;
        }
        let window = (gather.window)();
        let waited = began.elapsed();
        if waited >= window {
            return true;
        }
        std::thread::sleep(SLICE.min(window - waited));
    }
}

fn start_worker(gather: &Arc<Gather>) {
    if gather.running.swap(true, Ordering::SeqCst) {
        return;
    }
    let worker = Arc::clone(gather);
    let spawned = std::thread::Builder::new()
        .name("nrr-pass-window".into())
        .spawn(move || {
            let done = WorkerDone(worker);
            while done.0.pending.load(Ordering::SeqCst) {
                if !wait_out_window(&done.0) {
                    done.0.pending.store(false, Ordering::SeqCst);
                    return;
                }
                done.0.pending.store(false, Ordering::SeqCst);
                (done.0.inner)();
            }
        });
    if spawned.is_err() {
        // No thread to wait on: run the pass here, as an ungathered request.
        gather.running.store(false, Ordering::SeqCst);
        gather.pending.store(false, Ordering::SeqCst);
        (gather.inner)();
    }
}

/// `inner` for requests that may wait: they are answered by one pass after the
/// current window. While `window` says zero the pass runs at once on the
/// caller's thread, exactly as the plain hook would.
#[must_use]
pub fn gather(inner: RouteRecomputeHook, window: WindowFn) -> RouteRecomputeHook {
    gather_until(
        inner,
        window,
        Arc::new(crate::lifecycle::teardown_in_progress),
    )
}

/// [`gather`] with its own answer to "is the service stopping".
#[must_use]
pub fn gather_until(
    inner: RouteRecomputeHook,
    window: WindowFn,
    stopping: StopFn,
) -> RouteRecomputeHook {
    let gather = Arc::new(Gather {
        inner,
        window,
        stopping,
        pending: AtomicBool::new(false),
        running: AtomicBool::new(false),
    });
    Arc::new(move || {
        if (gather.window)().is_zero() {
            (gather.inner)();
            return;
        }
        gather.pending.store(true, Ordering::SeqCst);
        start_worker(&gather);
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

    fn counting() -> (RouteRecomputeHook, Arc<AtomicUsize>) {
        let runs = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&runs);
        (
            Arc::new(move || {
                counted.fetch_add(1, Ordering::SeqCst);
            }),
            runs,
        )
    }

    fn never() -> StopFn {
        Arc::new(|| false)
    }

    fn wait_until(done: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !done() {
            assert!(Instant::now() < deadline, "never happened");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    #[test]
    fn a_burst_of_requests_is_one_pass_after_the_window() {
        let (inner, runs) = counting();
        let hook = gather_until(inner, Arc::new(|| Duration::from_millis(80)), never());
        for _ in 0..50 {
            hook();
        }
        assert_eq!(
            runs.load(Ordering::SeqCst),
            0,
            "a request ran the pass on its caller's thread"
        );
        wait_until(|| runs.load(Ordering::SeqCst) >= 1);
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(runs.load(Ordering::SeqCst), 1, "the burst was not gathered");
    }

    #[test]
    fn a_request_after_the_pass_gets_its_own() {
        let (inner, runs) = counting();
        let hook = gather_until(inner, Arc::new(|| Duration::from_millis(10)), never());
        hook();
        wait_until(|| runs.load(Ordering::SeqCst) == 1);
        hook();
        wait_until(|| runs.load(Ordering::SeqCst) == 2);
    }

    #[test]
    fn with_no_window_the_pass_runs_before_the_call_returns() {
        let (inner, runs) = counting();
        let hook = gather_until(inner, Arc::new(|| Duration::ZERO), never());
        hook();
        hook();
        assert_eq!(runs.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn the_window_follows_the_posture() {
        assert_eq!(window_for(true), Duration::ZERO);
        assert_eq!(window_for(false), OBSERVATION_PASS_WINDOW);
    }

    #[test]
    fn a_panicking_pass_does_not_end_gathering() {
        let runs = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&runs);
        let hook = gather_until(
            Arc::new(move || {
                if counted.fetch_add(1, Ordering::SeqCst) == 0 {
                    panic!("pass blew up");
                }
            }),
            Arc::new(|| Duration::from_millis(5)),
            never(),
        );
        hook();
        wait_until(|| runs.load(Ordering::SeqCst) == 1);
        // The worker is gone with its panic; the flag must be clear again.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            hook();
            if runs.load(Ordering::SeqCst) >= 2 {
                break;
            }
            assert!(Instant::now() < deadline, "gathering ended with the panic");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn a_guard_arming_during_the_wait_ends_it_at_once() {
        use std::sync::atomic::AtomicU64;
        let (inner, runs) = counting();
        let window_ms = Arc::new(AtomicU64::new(30_000));
        let read = Arc::clone(&window_ms);
        let hook = gather_until(
            inner,
            Arc::new(move || Duration::from_millis(read.load(Ordering::SeqCst))),
            never(),
        );
        hook();
        std::thread::sleep(Duration::from_millis(250));
        assert_eq!(runs.load(Ordering::SeqCst), 0, "ran inside the window");
        let armed = Instant::now();
        window_ms.store(0, Ordering::SeqCst);
        wait_until(|| runs.load(Ordering::SeqCst) == 1);
        assert!(
            armed.elapsed() < Duration::from_secs(2),
            "the pass waited out the old window"
        );
    }

    #[test]
    fn no_pass_starts_once_the_service_is_stopping() {
        let (inner, runs) = counting();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let hook = gather_until(
            inner,
            Arc::new(|| Duration::from_millis(400)),
            Arc::new(move || flag.load(Ordering::SeqCst)),
        );
        hook();
        stop.store(true, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(700));
        assert_eq!(runs.load(Ordering::SeqCst), 0, "a pass ran after the stop");
    }
}
