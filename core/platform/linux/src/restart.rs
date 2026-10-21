//! Keeping a background reader of a system stream alive across restarts of
//! the thing it reads: a bounded backoff between attempts, and a stop that
//! reaches the thread whether it is waiting or blocked in a read.

// The Linux-only readers are its callers; the pure half is tested everywhere.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Duration;

/// Ends a read blocked on the current stream: shut its socket, kill its child.
pub(crate) type Interrupt = Box<dyn Fn() + Send>;

/// The wait between attempts: doubling from `first`, never past `cap`; the
/// caller goes back to `first` once a stream holds.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Backoff {
    pub(crate) first: Duration,
    pub(crate) cap: Duration,
}

impl Backoff {
    pub(crate) fn after(self, delay: Duration) -> Duration {
        delay.saturating_mul(2).min(self.cap)
    }
}

#[derive(Default)]
struct StopState {
    stopped: bool,
    interrupt: Option<Interrupt>,
}

/// Shutdown of one reader thread.
#[derive(Default)]
pub(crate) struct StopSignal {
    state: Mutex<StopState>,
    changed: Condvar,
}

impl StopSignal {
    fn lock(&self) -> MutexGuard<'_, StopState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(crate) fn stop(&self) {
        let mut state = self.lock();
        state.stopped = true;
        if let Some(interrupt) = state.interrupt.take() {
            interrupt();
        }
        self.changed.notify_all();
    }

    pub(crate) fn is_stopped(&self) -> bool {
        self.lock().stopped
    }

    /// Hold `interrupt` for the read about to start. `false` when already
    /// stopping; the stream is then ended at once.
    pub(crate) fn arm(&self, interrupt: Interrupt) -> bool {
        let mut state = self.lock();
        if state.stopped {
            interrupt();
            return false;
        }
        state.interrupt = Some(interrupt);
        true
    }

    pub(crate) fn disarm(&self) {
        self.lock().interrupt = None;
    }

    /// Sleep `delay` unless stopped first; `true` when stopping.
    pub(crate) fn wait(&self, delay: Duration) -> bool {
        let state = self.lock();
        let (state, _) = self
            .changed
            .wait_timeout_while(state, delay, |s| !s.stopped)
            .unwrap_or_else(|p| p.into_inner());
        state.stopped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[test]
    fn the_backoff_doubles_up_to_its_cap() {
        let backoff = Backoff {
            first: Duration::from_secs(1),
            cap: Duration::from_secs(30),
        };
        let mut delay = backoff.first;
        let mut seen = Vec::new();
        for _ in 0..7 {
            seen.push(delay.as_secs());
            delay = backoff.after(delay);
        }
        assert_eq!(seen, vec![1, 2, 4, 8, 16, 30, 30]);
    }

    #[test]
    fn a_stop_ends_a_wait_and_fires_the_armed_interrupt_once() {
        let stop = Arc::new(StopSignal::default());
        let fired = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&fired);
        assert!(stop.arm(Box::new(move || {
            counter.fetch_add(1, Ordering::Relaxed);
        })));
        let waiter = Arc::clone(&stop);
        let thread = std::thread::spawn(move || waiter.wait(Duration::from_secs(3600)));
        stop.stop();
        assert!(thread.join().expect("the wait returns"));
        stop.stop();
        assert_eq!(fired.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_stream_armed_after_the_stop_is_ended_at_once() {
        let stop = StopSignal::default();
        stop.stop();
        let fired = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&fired);
        assert!(!stop.arm(Box::new(move || {
            counter.fetch_add(1, Ordering::Relaxed);
        })));
        assert_eq!(fired.load(Ordering::Relaxed), 1);
        assert!(stop.wait(Duration::from_secs(3600)));
    }

    #[test]
    fn a_disarmed_stream_is_not_interrupted() {
        let stop = StopSignal::default();
        let fired = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&fired);
        assert!(stop.arm(Box::new(move || {
            counter.fetch_add(1, Ordering::Relaxed);
        })));
        stop.disarm();
        stop.stop();
        assert_eq!(fired.load(Ordering::Relaxed), 0);
        assert!(stop.is_stopped());
    }
}
