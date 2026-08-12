//! Session registry of destinations POSITIVELY established
//! as DIRECT (non-rule) hosts, for kill-switch block-all exemptions.
//!
//! The catch-all block-all (`FailClosedUnknown` / `kill_switch_block_all`) cuts
//! every destination it cannot classify. Rule hosts escape via their compiled
//! permits, but a DIRECT host — one no rule matches — has no permit at all, so
//! it is cut too (the habr.com case: the secondary adapter vanished
//! after a BSOD, the block-all armed, and a plain primary-path site died).
//!
//! This registry collects addresses two provers feed in:
//!
//! 1. **The Mode-B resolver** (`DirectAnswerGate`): a non-rule `A` answer that
//!    passed direct-answer steering is provably NOT secondary-owned —
//!    we just filtered every secondary-pinned address out of it.
//! 2. **The FCrDNS learner** (`learn_reverse_confirmed_direct`): a dropped IP
//!    whose forward-confirmed PTR name matches NO rule is provably a direct
//!    destination (the DoH / browser-cache blind spot — the resolver never saw
//!    the query, so prover 1 could not run).
//!
//! The orchestrator snapshots the registry at the block-all call site,
//! subtracts anything secondary-destined (defense in depth — the provers
//! already exclude those), and emits ALE + packet-layer permits above the
//! catch-all. Session-scoped like the FCrDNS attempt set: the block-all is a
//! transient posture, and a service restart starts clean.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::Mutex;

use crate::net_filter::is_non_routable_v4;

/// Default capacity bound. Each registered IP costs two WFP filters (an ALE
/// exempt + a packet-layer permit), so the cap bounds the installed-filter
/// growth a long armed window can produce. At the cap, new registrations are
/// refused (WARN once) — the steady state degrades to "recently learned hosts
/// stay reachable", never to unbounded filter churn.
pub const DEFAULT_KNOWN_DIRECT_CAP: usize = 1024;

/// Thread-safe, capped, session-scoped set of known-direct IPv4 destinations.
pub struct KnownDirectRegistry {
    ips: Mutex<HashSet<Ipv4Addr>>,
    cap: usize,
    cap_warned: Mutex<bool>,
}

impl Default for KnownDirectRegistry {
    fn default() -> Self {
        Self::new(DEFAULT_KNOWN_DIRECT_CAP)
    }
}

impl KnownDirectRegistry {
    pub fn new(cap: usize) -> Self {
        Self {
            ips: Mutex::new(HashSet::new()),
            cap,
            cap_warned: Mutex::new(false),
        }
    }

    /// Register `addresses` as known-direct. Non-routable addresses (loopback
    /// / unspecified — the hosts-file-pin shapes) are ignored; anything the
    /// codegen must never permit per-host (link-local, broadcast) is filtered
    /// again at emission via `is_exempt_from_blocking`. Returns how many
    /// addresses were NEWLY added (0 ⇒ the caller can skip its reconcile —
    /// nothing to install).
    pub fn register(&self, addresses: &[Ipv4Addr]) -> usize {
        let mut set = self.ips.lock().unwrap_or_else(|p| p.into_inner());
        let mut added = 0usize;
        for ip in addresses
            .iter()
            .filter(|ip| !is_non_routable_v4(ip))
            .copied()
        {
            if set.contains(&ip) {
                continue;
            }
            if set.len() >= self.cap {
                let mut warned = self.cap_warned.lock().unwrap_or_else(|p| p.into_inner());
                if !*warned {
                    *warned = true;
                    tracing::warn!(
                        target: "nrr::killswitch",
                        cap = self.cap,
                        "known-direct registry is full — further direct hosts stay blocked under the block-all until it disarms (session cap)",
                    );
                }
                break;
            }
            set.insert(ip);
            added += 1;
        }
        added
    }

    /// Sorted snapshot for the codegen. Sorted so the desired filter set is
    /// deterministic across compute ticks — the reconcile diff must see "no
    /// change" whenever the registry has not changed.
    pub fn snapshot(&self) -> Vec<Ipv4Addr> {
        let set = self.ips.lock().unwrap_or_else(|p| p.into_inner());
        let mut ips: Vec<Ipv4Addr> = set.iter().copied().collect();
        ips.sort_unstable();
        ips
    }

    /// Number of registered addresses (diagnostics).
    pub fn len(&self) -> usize {
        self.ips.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    #[test]
    fn registers_routable_and_ignores_non_routable() {
        let r = KnownDirectRegistry::new(16);
        let added = r.register(&[
            ip(178, 248, 237, 68), // habr.com — routable
            ip(127, 0, 0, 1),      // loopback (hosts-file pin) — ignored
            ip(0, 0, 0, 0),        // unspecified (adblock pin) — ignored
        ]);
        assert_eq!(added, 1);
        assert_eq!(r.snapshot(), vec![ip(178, 248, 237, 68)]);
    }

    #[test]
    fn re_registering_known_addresses_adds_nothing() {
        let r = KnownDirectRegistry::new(16);
        assert_eq!(r.register(&[ip(1, 1, 1, 1)]), 1);
        assert_eq!(
            r.register(&[ip(1, 1, 1, 1)]),
            0,
            "0 ⇒ caller skips its sync reconcile"
        );
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn snapshot_is_sorted_and_stable() {
        let r = KnownDirectRegistry::new(16);
        r.register(&[ip(9, 9, 9, 9), ip(1, 1, 1, 1), ip(5, 5, 5, 5)]);
        let a = r.snapshot();
        let b = r.snapshot();
        assert_eq!(a, vec![ip(1, 1, 1, 1), ip(5, 5, 5, 5), ip(9, 9, 9, 9)]);
        assert_eq!(a, b, "identical registry ⇒ identical desired set");
    }

    #[test]
    fn cap_refuses_overflow_but_keeps_existing() {
        let r = KnownDirectRegistry::new(2);
        assert_eq!(r.register(&[ip(1, 1, 1, 1), ip(2, 2, 2, 2)]), 2);
        assert_eq!(r.register(&[ip(3, 3, 3, 3)]), 0, "cap reached");
        assert_eq!(r.len(), 2);
        // Existing entries still re-register as no-ops.
        assert_eq!(r.register(&[ip(1, 1, 1, 1)]), 0);
    }
}
