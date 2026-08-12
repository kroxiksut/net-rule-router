//! Active reachability probe — the neutral port (policy/mechanism seam).
//!
//! The route table can't tell a dead-but-`Up` tunnel (adapter keeps `Up + IPv4`)
//! from a healthy one, because NetRuleRouter itself owns/mutates the route table
//! (it strips the secondary adapter's catch-all and installs its own `/32`s). The
//! only reliable non-inferential liveness signal is an ACTIVE probe: ping the
//! next-hop and see if it answers.
//!
//! This module holds only the neutral [`ReachabilityProbe`] trait plus the two
//! OS-agnostic implementations (a feature-disabled default and a test mock). The
//! real mechanism (Windows `IcmpSendEcho`; Linux/macOS raw-socket or `ping`
//! later) lives in the per-OS backend and `impl`s this trait.
//!
//! ## Fail-SAFE direction
//!
//! A probe that CANNOT be run (handle-open failure, send error) returns `true`
//! (reachable). Only a definite *no reply within the timeout* returns `false`.
//! This is deliberate: the caller uses a `false` to eventually fail-close (block)
//! the user's traffic, so an indeterminate probe must never be the thing that
//! blocks a working secondary adapter. Transient loss is absorbed by the caller's
//! hysteresis (a single `false` never fail-closes).

use std::net::Ipv4Addr;
use std::time::Duration;

/// Probes whether an IPv4 next-hop answers an ICMP echo. Neutral interface; the
/// Windows impl uses `IcmpSendEcho`. Linux/macOS get their own impls later.
pub trait ReachabilityProbe: Send + Sync {
    /// `true` if `target` answered within `timeout`, OR if the probe could not
    /// be run at all (fail-safe — an indeterminate result must not fail-close).
    /// `false` ONLY on a definite no-reply-within-timeout.
    fn is_reachable(&self, target: Ipv4Addr, timeout: Duration) -> bool;
}

/// Always-reachable probe: the feature-disabled default and the non-implementing
/// platform placeholder. Never reports a target as dead, so it can never
/// fail-close.
#[derive(Debug, Default, Clone, Copy)]
pub struct AlwaysReachableProbe;

impl ReachabilityProbe for AlwaysReachableProbe {
    fn is_reachable(&self, _target: Ipv4Addr, _timeout: Duration) -> bool {
        true
    }
}

/// Deterministic probe for tests: reports a fixed verdict.
#[derive(Debug, Clone)]
pub struct MockReachabilityProbe {
    reachable: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl MockReachabilityProbe {
    pub fn new(reachable: bool) -> Self {
        Self {
            reachable: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(reachable)),
        }
    }
    /// Flip the verdict at runtime (simulate a tunnel dying / recovering).
    pub fn set_reachable(&self, reachable: bool) {
        self.reachable
            .store(reachable, std::sync::atomic::Ordering::SeqCst);
    }
}

impl ReachabilityProbe for MockReachabilityProbe {
    fn is_reachable(&self, _target: Ipv4Addr, _timeout: Duration) -> bool {
        self.reachable.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_reachable_never_reports_dead() {
        let probe = AlwaysReachableProbe;
        assert!(probe.is_reachable(Ipv4Addr::new(10, 0, 0, 1), Duration::from_millis(100)));
    }

    #[test]
    fn mock_reflects_its_flag_and_flips() {
        let probe = MockReachabilityProbe::new(true);
        let t = Ipv4Addr::new(10, 0, 0, 1);
        assert!(probe.is_reachable(t, Duration::from_millis(10)));
        probe.set_reachable(false);
        assert!(!probe.is_reachable(t, Duration::from_millis(10)));
    }
}
