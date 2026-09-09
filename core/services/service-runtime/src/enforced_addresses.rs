//! Destination addresses the machine is ENFORCING right now, per principal.
//!
//! ## Why this exists separately from the FQDN cache
//!
//! Before handing a rule host's addresses to a client, the resolver has to know
//! whether a connection to them will be carried by the policy or dropped by it.
//! It used to ask the FQDN cache, which answers a different question: "has this
//! name ever resolved to this address". The two diverge by a whole apply cycle —
//! the cache learns a fact the instant the answer arrives, while the route and
//! the kill-switch pin that make the address usable land on the next reconcile.
//! On the machine that reported this, that reconcile ran 10 s at the median, so
//! every answer in the window went out ahead of its own enforcement and the
//! client's first connect was dropped.
//!
//! The two also diverge in the steady state, in both directions: the pin set is
//! trimmed every pass (a main-link-claimed address is deliberately not pinned),
//! per-app destination lists have a cap that evicts, and a CDN hands out new
//! addresses for a name whose old ones are still cached.
//!
//! So the apply publishes what it actually installed, and the resolver reads
//! that. The register is a mirror of the last successful apply — never a
//! prediction, never a plan.
//!
//! ## Bounds and staleness
//!
//! In-memory, per service run, one address set per principal. It is replaced
//! wholesale by each successful apply, so it cannot grow without bound and
//! cannot hold an address the policy has stopped enforcing. An empty answer
//! ("nothing published yet") is honest: before the first apply nothing IS
//! enforced, and the resolver must not pretend otherwise.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, OnceLock};

/// What the last successful apply installed enforcement for, keyed by SID.
#[derive(Default)]
pub struct EnforcedAddressRegister {
    per_sid: Mutex<HashMap<String, Arc<HashSet<Ipv4Addr>>>>,
}

impl EnforcedAddressRegister {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace `sid`'s set with what the apply just installed. Wholesale, not
    /// additive: an address the apply stopped covering must stop reading as
    /// enforced, or the resolver would keep handing out an address whose pin
    /// and route are gone.
    pub fn publish<I: IntoIterator<Item = Ipv4Addr>>(&self, sid: &str, addresses: I) {
        let set: HashSet<Ipv4Addr> = addresses.into_iter().collect();
        self.per_sid
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(sid.to_string(), Arc::new(set));
    }

    /// Drop `sid` entirely — the principal's filters were removed, so nothing
    /// of theirs is enforced any more.
    pub fn forget(&self, sid: &str) {
        self.per_sid
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(sid);
    }

    /// `sid`'s enforced set. Empty when the principal has never applied — which
    /// is the truth, not a missing answer.
    pub fn snapshot(&self, sid: &str) -> Arc<HashSet<Ipv4Addr>> {
        self.per_sid
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .map(Arc::clone)
            .unwrap_or_default()
    }

    /// Whether a connection to `ip` is carried by `sid`'s installed policy.
    pub fn is_enforced(&self, sid: &str, ip: Ipv4Addr) -> bool {
        self.snapshot(sid).contains(&ip)
    }
}

static GLOBAL_ENFORCED_ADDRESSES: OnceLock<Arc<EnforcedAddressRegister>> = OnceLock::new();

/// Process-wide register. The per-SID apply publishes into it; the resolver
/// reads it while choosing which addresses to answer with. Tests construct
/// [`EnforcedAddressRegister`] directly and never touch this.
pub fn global_enforced_addresses() -> Arc<EnforcedAddressRegister> {
    GLOBAL_ENFORCED_ADDRESSES
        .get_or_init(|| Arc::new(EnforcedAddressRegister::new()))
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(d: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, d)
    }

    #[test]
    fn an_unpublished_principal_enforces_nothing() {
        let reg = EnforcedAddressRegister::new();
        assert!(!reg.is_enforced("S-1-5-21-A", ip(50)));
        assert!(reg.snapshot("S-1-5-21-A").is_empty());
    }

    #[test]
    fn publish_replaces_rather_than_accumulates() {
        let reg = EnforcedAddressRegister::new();
        reg.publish("S-1-5-21-A", [ip(50), ip(51)]);
        assert!(reg.is_enforced("S-1-5-21-A", ip(50)));

        // The next apply no longer covers .50 — it must stop reading as
        // enforced, or the resolver keeps answering with a dead address.
        reg.publish("S-1-5-21-A", [ip(51)]);
        assert!(!reg.is_enforced("S-1-5-21-A", ip(50)));
        assert!(reg.is_enforced("S-1-5-21-A", ip(51)));
    }

    #[test]
    fn principals_do_not_see_each_others_addresses() {
        let reg = EnforcedAddressRegister::new();
        reg.publish("S-1-5-21-A", [ip(50)]);
        reg.publish("S-1-5-21-B", [ip(51)]);
        assert!(!reg.is_enforced("S-1-5-21-B", ip(50)));
        assert!(!reg.is_enforced("S-1-5-21-A", ip(51)));
    }

    #[test]
    fn forgetting_a_principal_clears_its_set() {
        let reg = EnforcedAddressRegister::new();
        reg.publish("S-1-5-21-A", [ip(50)]);
        reg.forget("S-1-5-21-A");
        assert!(!reg.is_enforced("S-1-5-21-A", ip(50)));
    }
}
