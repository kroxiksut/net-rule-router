//! Coalesced live applies of the fake-IP toggle.
//!
//! Every settings save asks the stack to match the stored toggle, and an apply
//! may rebuild the TUN adapter. Applied one thread per save, repeated clicks
//! rebuilt it once per click and could land out of order, leaving the stack
//! opposite to what was stored. The queue applies only the latest request, on
//! one worker, once the saves have been quiet for a short window.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::production_settings::FakeIpApplyRequest;

/// How long the saves must stop before the latest one is applied: longer than
/// a double click, short next to the seconds a driver load takes.
pub const FAKE_IP_APPLY_QUIET: Duration = Duration::from_millis(500);

/// The apply itself: reconcile the stack, replan, flush.
pub type FakeIpApplyFn = Arc<dyn Fn(FakeIpApplyRequest) + Send + Sync>;

/// See the module docs. Cheap to call from an IPC handler: `submit` never
/// waits for an apply.
pub struct FakeIpApplyQueue {
    shared: Arc<Shared>,
}

struct Shared {
    quiet: Duration,
    apply: FakeIpApplyFn,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    pending: Option<Pending>,
    worker_running: bool,
}

struct Pending {
    request: FakeIpApplyRequest,
    last_at: Instant,
}

enum Next {
    Apply(FakeIpApplyRequest),
    Wait(Duration),
    Done,
}

impl FakeIpApplyQueue {
    #[must_use]
    pub fn new(quiet: Duration, apply: FakeIpApplyFn) -> Self {
        Self {
            shared: Arc::new(Shared {
                quiet,
                apply,
                state: Mutex::new(State::default()),
            }),
        }
    }

    /// Queue `request`, folding it into one not yet applied.
    pub fn submit(&self, request: FakeIpApplyRequest) {
        let start_worker = {
            let mut state = self.shared.lock();
            let request = match state.pending.take() {
                Some(earlier) => merge(earlier.request, request),
                None => request,
            };
            state.pending = Some(Pending {
                request,
                last_at: Instant::now(),
            });
            !std::mem::replace(&mut state.worker_running, true)
        };
        if !start_worker {
            return;
        }
        let shared = Arc::clone(&self.shared);
        let spawned = std::thread::Builder::new()
            .name("nrr-fakeip-apply".to_string())
            .spawn(move || shared.run());
        if let Err(error) = spawned {
            // Without a worker the choice is applied here rather than lost.
            tracing::warn!(
                target: "nrr::fake-ip",
                error = %error,
                "fake-IP apply worker failed to spawn; applying on the caller's thread",
            );
            let pending = {
                let mut state = self.shared.lock();
                state.worker_running = false;
                state.pending.take()
            };
            if let Some(pending) = pending {
                self.shared.apply_contained(pending.request);
            }
        }
    }
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn run(&self) {
        loop {
            let next = {
                let mut state = self.lock();
                match state.pending.as_ref().map(|p| p.last_at.elapsed()) {
                    None => {
                        // Cleared under the lock, so a racing `submit` either
                        // lands before this and is applied, or starts a worker.
                        state.worker_running = false;
                        Next::Done
                    }
                    Some(waited) if waited >= self.quiet => state
                        .pending
                        .take()
                        .map_or(Next::Wait(Duration::ZERO), |p| Next::Apply(p.request)),
                    Some(waited) => Next::Wait(self.quiet - waited),
                }
            };
            match next {
                Next::Apply(request) => self.apply_contained(request),
                Next::Wait(wait) => std::thread::sleep(wait),
                Next::Done => return,
            }
        }
    }

    /// A panicking apply must not take the worker with it: every later toggle
    /// would then be stored and never applied.
    fn apply_contained(&self, request: FakeIpApplyRequest) {
        let desired = request.desired;
        if catch_unwind(AssertUnwindSafe(|| (self.apply)(request))).is_err() {
            tracing::warn!(
                target: "nrr::fake-ip",
                desired,
                "fake-IP live apply panicked; the next settings save retries it",
            );
        }
    }
}

/// The later request decides the state; a flush reason of either survives,
/// since answers cached before the earlier save may still describe it.
fn merge(earlier: FakeIpApplyRequest, later: FakeIpApplyRequest) -> FakeIpApplyRequest {
    let mut dns_flush_reasons = earlier.dns_flush_reasons;
    for reason in later.dns_flush_reasons {
        if !dns_flush_reasons.contains(&reason) {
            dns_flush_reasons.push(reason);
        }
    }
    FakeIpApplyRequest {
        desired: later.desired,
        dns_flush_reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Calls = Arc<Mutex<Vec<FakeIpApplyRequest>>>;

    fn recording(quiet: Duration) -> (FakeIpApplyQueue, Calls) {
        let calls: Calls = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&calls);
        let queue = FakeIpApplyQueue::new(
            quiet,
            Arc::new(move |req: FakeIpApplyRequest| {
                sink.lock().unwrap_or_else(|p| p.into_inner()).push(req);
            }),
        );
        (queue, calls)
    }

    fn request(desired: bool, reasons: &[&'static str]) -> FakeIpApplyRequest {
        FakeIpApplyRequest {
            desired,
            dns_flush_reasons: reasons.to_vec(),
        }
    }

    fn wait_for(calls: &Calls, count: usize) -> Vec<FakeIpApplyRequest> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let seen = calls.lock().unwrap_or_else(|p| p.into_inner()).clone();
            if seen.len() >= count || Instant::now() > deadline {
                return seen;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn a_burst_of_clicks_applies_once_with_the_last_state() {
        let (queue, calls) = recording(Duration::from_millis(300));
        queue.submit(request(true, &["fake_ip_enabled"]));
        queue.submit(request(false, &["fake_ip_enabled"]));
        queue.submit(request(true, &["enforcement_mode", "fake_ip_enabled"]));

        let seen = wait_for(&calls, 1);
        std::thread::sleep(Duration::from_millis(400));
        let seen_later = calls.lock().unwrap_or_else(|p| p.into_inner()).clone();
        assert_eq!(seen, seen_later, "nothing else is applied after the burst");
        assert_eq!(
            seen,
            vec![request(true, &["fake_ip_enabled", "enforcement_mode"])]
        );
    }

    #[test]
    fn the_last_click_wins_even_when_it_turns_the_feature_off() {
        let (queue, calls) = recording(Duration::from_millis(300));
        queue.submit(request(true, &["fake_ip_enabled"]));
        queue.submit(request(false, &["fake_ip_enabled"]));
        let seen = wait_for(&calls, 1);
        assert_eq!(seen.len(), 1);
        assert!(!seen[0].desired);
    }

    #[test]
    fn a_save_after_the_quiet_window_is_applied_again() {
        let (queue, calls) = recording(Duration::from_millis(20));
        queue.submit(request(true, &[]));
        assert_eq!(wait_for(&calls, 1).len(), 1);
        queue.submit(request(false, &["fake_ip_enabled"]));
        let seen = wait_for(&calls, 2);
        assert_eq!(
            seen,
            vec![request(true, &[]), request(false, &["fake_ip_enabled"])]
        );
    }

    #[test]
    fn a_panicking_apply_does_not_stop_later_ones() {
        let calls: Calls = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&calls);
        let queue = FakeIpApplyQueue::new(
            Duration::from_millis(20),
            Arc::new(move |req: FakeIpApplyRequest| {
                let mut seen = sink.lock().unwrap_or_else(|p| p.into_inner());
                seen.push(req);
                if seen.len() == 1 {
                    drop(seen);
                    panic!("first apply fails");
                }
            }),
        );
        queue.submit(request(true, &[]));
        assert_eq!(wait_for(&calls, 1).len(), 1);
        queue.submit(request(false, &[]));
        let seen = wait_for(&calls, 2);
        assert_eq!(seen.len(), 2, "the worker survived the panic");
        assert!(!seen[1].desired);
    }
}
