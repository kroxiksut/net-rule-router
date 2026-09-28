//! One activation at a time, machine-wide.
//!
//! An activation runs in phases (mark, apply per SID, commit the pointer) and
//! a baseline activation touches several SIDs at once, so a per-SID lock does
//! not keep two of them apart: one could apply its filters while the other
//! commits its pointer, leaving a SID enforcing one revision and recording
//! another. Activations are rare and user-initiated; queueing them costs a few
//! seconds at worst.
//!
//! The wait is bounded so a stuck activation turns later ones into a visible
//! "busy" instead of a pile of parked worker threads.

use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// Below the client's 30 s budget for `mutation.submit`, so a refusal reaches
/// the user as "busy" rather than as a timeout.
pub(super) const ACTIVATION_GATE_WAIT: Duration = Duration::from_secs(20);

#[derive(Debug, Default)]
pub(super) struct ActivationGate {
    busy: Mutex<bool>,
    freed: Condvar,
}

impl ActivationGate {
    /// Wait up to `wait` for the gate. `None` when it stayed taken.
    pub(super) fn enter(&self, wait: Duration) -> Option<ActivationPass<'_>> {
        let deadline = Instant::now() + wait;
        let mut busy = self.busy.lock().unwrap_or_else(|p| p.into_inner());
        while *busy {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            busy = self
                .freed
                .wait_timeout(busy, left)
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
        *busy = true;
        Some(ActivationPass { gate: self })
    }
}

/// Held for the whole activation; releases on drop, panics included.
#[must_use = "dropping the pass ends the activation's exclusive window"]
pub(super) struct ActivationPass<'a> {
    gate: &'a ActivationGate,
}

impl Drop for ActivationPass<'_> {
    fn drop(&mut self) {
        *self.gate.busy.lock().unwrap_or_else(|p| p.into_inner()) = false;
        self.gate.freed.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn activations_never_overlap() {
        let gate = Arc::new(ActivationGate::default());
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let workers: Vec<_> = (0..4)
            .map(|_| {
                let (gate, running, peak) =
                    (Arc::clone(&gate), Arc::clone(&running), Arc::clone(&peak));
                thread::spawn(move || {
                    let _pass = gate.enter(Duration::from_secs(10)).expect("admitted");
                    let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(20));
                    running.fetch_sub(1, Ordering::SeqCst);
                })
            })
            .collect();
        for worker in workers {
            worker.join().expect("worker");
        }
        assert_eq!(peak.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_held_gate_refuses_after_the_wait() {
        let gate = ActivationGate::default();
        let _held = gate.enter(Duration::ZERO).expect("free");
        assert!(gate.enter(Duration::from_millis(30)).is_none());
    }

    #[test]
    fn a_panicking_activation_frees_the_gate() {
        let gate = Arc::new(ActivationGate::default());
        let moved = Arc::clone(&gate);
        let outcome = thread::spawn(move || {
            let _pass = moved.enter(Duration::ZERO).expect("free");
            panic!("apply blew up");
        })
        .join();
        assert!(outcome.is_err());
        assert!(gate.enter(Duration::ZERO).is_some());
    }
}
