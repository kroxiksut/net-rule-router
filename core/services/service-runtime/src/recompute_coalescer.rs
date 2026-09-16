//! One enforcement pass at a time, however many callers ask for one.
//!
//! The recompute hook is called from the adapter monitor, the safety tick, the
//! DNS refresh, the rule-host seed and the resolver's answer gate. Unserialised,
//! five of them started within five seconds of a boot and each took 15-24 s
//! fighting the others for the same locks, where one pass alone takes 1-3 s.
//!
//! The contract callers rely on is kept: `hook()` returns only after a pass that
//! STARTED after the call has finished, so whatever the caller recorded before
//! calling is enforced. Callers that arrive while a pass runs share the next one.

use std::sync::{Arc, Condvar, Mutex};

use crate::supervised_runtime::RouteRecomputeHook;

#[derive(Default)]
struct State {
    /// Highest request number handed out.
    requested: u64,
    /// Highest request a finished pass is known to cover.
    completed: u64,
    running: bool,
}

struct Coalescer {
    inner: RouteRecomputeHook,
    state: Mutex<State>,
    finished: Condvar,
}

/// Clears `running` even when the pass panics, so the callers waiting on it are
/// not stranded behind a pass that will never report.
struct PassGuard<'a> {
    coalescer: &'a Coalescer,
    covers: u64,
    finished: bool,
}

impl Drop for PassGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.coalescer.lock();
        state.running = false;
        if self.finished {
            state.completed = state.completed.max(self.covers);
        }
        drop(state);
        self.coalescer.finished.notify_all();
    }
}

impl Coalescer {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn call(&self) {
        let mut state = self.lock();
        state.requested += 1;
        let mine = state.requested;
        loop {
            if state.completed >= mine {
                return;
            }
            if !state.running {
                // This caller runs the pass, on its own thread, for every
                // request registered up to now.
                state.running = true;
                let mut guard = PassGuard {
                    coalescer: self,
                    covers: state.requested,
                    finished: false,
                };
                drop(state);
                (self.inner)();
                guard.finished = true;
                drop(guard);
                state = self.lock();
                continue;
            }
            state = self.finished.wait(state).unwrap_or_else(|p| p.into_inner());
        }
    }
}

/// Wrap `inner` so concurrent calls never run it side by side.
///
/// Must not be called from inside `inner` on the same thread: the call would
/// wait for the pass it is part of.
#[must_use]
pub fn coalesce(inner: RouteRecomputeHook) -> RouteRecomputeHook {
    let coalescer = Arc::new(Coalescer {
        inner,
        state: Mutex::new(State::default()),
        finished: Condvar::new(),
    });
    Arc::new(move || coalescer.call())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// A pass that takes `ms` and counts how many ran and how many overlapped.
    fn slow_pass(ms: u64) -> (RouteRecomputeHook, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let runs = Arc::new(AtomicUsize::new(0));
        let overlaps = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let hook = {
            let (runs, overlaps, active) = (runs.clone(), overlaps.clone(), active);
            Arc::new(move || {
                if active.fetch_add(1, Ordering::SeqCst) > 0 {
                    overlaps.fetch_add(1, Ordering::SeqCst);
                }
                runs.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(ms));
                active.fetch_sub(1, Ordering::SeqCst);
            }) as RouteRecomputeHook
        };
        (hook, runs, overlaps)
    }

    #[test]
    fn a_burst_of_callers_never_runs_passes_side_by_side_and_shares_them() {
        let (inner, runs, overlaps) = slow_pass(60);
        let hook = coalesce(inner);
        let callers: Vec<_> = (0..8)
            .map(|_| {
                let hook = hook.clone();
                std::thread::spawn(move || hook())
            })
            .collect();
        for caller in callers {
            caller.join().expect("caller");
        }
        assert_eq!(overlaps.load(Ordering::SeqCst), 0);
        let runs = runs.load(Ordering::SeqCst);
        assert!((1..=3).contains(&runs), "eight callers took {runs} passes");
    }

    /// The caller's change landed before it called; a pass that was already
    /// running when it called may have read state from before the change.
    #[test]
    fn a_caller_arriving_mid_pass_waits_for_a_pass_that_started_after_it() {
        let started = Arc::new(AtomicUsize::new(0));
        let change_seen_by = Arc::new(AtomicUsize::new(usize::MAX));
        let change = Arc::new(AtomicUsize::new(0));
        let inner = {
            let (started, change_seen_by, change) =
                (started.clone(), change_seen_by.clone(), change.clone());
            Arc::new(move || {
                let sees_change = change.load(Ordering::SeqCst) == 1;
                let n = started.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(80));
                if sees_change {
                    change_seen_by.fetch_min(n, Ordering::SeqCst);
                }
            }) as RouteRecomputeHook
        };
        let hook = coalesce(inner);
        let first = {
            let hook = hook.clone();
            std::thread::spawn(move || hook())
        };
        while started.load(Ordering::SeqCst) == 0 {
            std::thread::yield_now();
        }
        change.store(1, Ordering::SeqCst);
        hook();
        assert_eq!(
            change_seen_by.load(Ordering::SeqCst),
            1,
            "returned before a pass saw the change"
        );
        first.join().expect("first caller");
    }

    #[test]
    fn a_panicking_pass_does_not_strand_the_next_caller() {
        let calls = Arc::new(AtomicUsize::new(0));
        let inner = {
            let calls = calls.clone();
            Arc::new(move || {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    panic!("first pass fails");
                }
            }) as RouteRecomputeHook
        };
        let hook = coalesce(inner);
        let failed = {
            let hook = hook.clone();
            std::thread::spawn(move || hook())
        };
        assert!(failed.join().is_err());
        hook();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
