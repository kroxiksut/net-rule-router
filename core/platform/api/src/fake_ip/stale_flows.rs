//! Fake-IP — the neutral "tear down flows the last run left behind" contract.
//!
//! Fake addresses outlive a service restart on purpose: a hostname keeps its
//! address as a stable identity. The userspace TCP stack behind those addresses
//! does not — it is rebuilt empty on every start. An application that still
//! holds a socket to a fake address is therefore talking to a peer that no
//! longer exists on the other side, and nothing tells it so: no reset arrives,
//! the socket stays "established", and a browser will sit on it instead of
//! re-resolving. The visible symptom is a page whose images never load while
//! the service looks perfectly healthy.
//!
//! Per the policy/mechanism seam this trait is the mechanism half: an
//! implementation asks the OS to tear down established TCP connections whose
//! remote address falls inside a given range. WHICH range (the fake-IP pool)
//! and WHEN to do it (once, as the stack comes up) stay neutral in
//! `service-runtime`.
//!
//! Tearing down is best-effort by construction: a socket may close on its own
//! between listing and teardown, the platform may expose no such control, or a
//! single row may be refused while the rest succeed. None of that is fatal —
//! the worst case is the old behaviour, an application waiting on a dead
//! socket, so callers log the outcome and carry on.

use std::net::Ipv4Addr;
use std::sync::Mutex;

/// What one teardown pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StaleFlowSweep {
    /// Connections found inside the range.
    pub found: usize,
    /// Of those, the ones the OS agreed to tear down.
    pub torn_down: usize,
}

impl StaleFlowSweep {
    /// Nothing was in range — the common case on a clean start.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.found == 0
    }
}

/// Tear down established TCP connections aimed at a range of addresses.
pub trait StaleFlowReset: Send + Sync {
    /// Tear down every established TCP connection whose REMOTE address falls
    /// inside `base`/`prefix_len`. Returns what the pass found and closed.
    ///
    /// Called once as the stack comes up, so it may read the whole connection
    /// table, but it must not block for long: a slow sweep delays the moment
    /// policy starts being enforced.
    fn reset_flows_to(&self, base: Ipv4Addr, prefix_len: u8) -> StaleFlowSweep;
}

/// The default: tears nothing down. Used on platforms with no connection-table
/// control wired, and as the inert default so the stack comes up unchanged when
/// the sweep is not configured.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopStaleFlowReset;

impl StaleFlowReset for NoopStaleFlowReset {
    fn reset_flows_to(&self, _base: Ipv4Addr, _prefix_len: u8) -> StaleFlowSweep {
        StaleFlowSweep::default()
    }
}

/// Test double: reports a fixed sweep and records the ranges it was asked
/// about, so a test can prove the stack swept the pool exactly once.
#[derive(Debug, Default)]
pub struct MockStaleFlowReset {
    inner: Mutex<MockInner>,
}

#[derive(Debug, Default)]
struct MockInner {
    calls: Vec<(Ipv4Addr, u8)>,
    answer: StaleFlowSweep,
}

impl MockStaleFlowReset {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set what the next sweeps report.
    pub fn set_answer(&self, answer: StaleFlowSweep) {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).answer = answer;
    }

    /// Ranges this double was asked to sweep, in call order.
    #[must_use]
    pub fn calls(&self) -> Vec<(Ipv4Addr, u8)> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .calls
            .clone()
    }
}

impl StaleFlowReset for MockStaleFlowReset {
    fn reset_flows_to(&self, base: Ipv4Addr, prefix_len: u8) -> StaleFlowSweep {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.calls.push((base, prefix_len));
        inner.answer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POOL: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 0);

    #[test]
    fn noop_tears_nothing_down() {
        let sweep = NoopStaleFlowReset.reset_flows_to(POOL, 15);
        assert_eq!(sweep, StaleFlowSweep::default());
        assert!(sweep.is_empty());
    }

    #[test]
    fn mock_records_the_range_and_reports_its_answer() {
        let mock = MockStaleFlowReset::new();
        mock.set_answer(StaleFlowSweep {
            found: 8,
            torn_down: 7,
        });

        let sweep = mock.reset_flows_to(POOL, 15);

        assert_eq!(sweep.found, 8);
        assert_eq!(sweep.torn_down, 7);
        assert!(!sweep.is_empty());
        assert_eq!(mock.calls(), vec![(POOL, 15)]);
    }
}
