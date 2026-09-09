//! Names for addresses NO rule covers — so a site that fails on the main link
//! can be named before anyone has a theory about it.
//!
//! ## The gap this closes
//!
//! The connection observer reports how each destination fares on the main link
//! by ADDRESS, and turning that into a hostname goes through
//! [`crate::recent_rule_addresses`] — which, by design, only remembers what a
//! RULE host resolved to. So the one host the user most needs told about, the
//! one with no rule yet, was the one whose failures could never be named.
//!
//! Field case: `forum.talk.example` completes its TCP handshake on the main
//! link and is then dropped mid-handshake by the operator, keyed on the name it
//! asked for — the apex answers on the same address. Every retransmit was
//! observed and every one was discarded for want of a name.
//!
//! ## The boundary
//!
//! This index is DIAGNOSTIC. A name here says only "we saw this address
//! answered for this host"; it is not evidence a rule covers anything, and it
//! must never reach the enforcement path — the FCrDNS learner, the cache, a pin.
//! That is why it is a distinct type over the same storage rather than more
//! entries in the rule index: the compiler refuses the mix-up that a shared type
//! would let through silently.
//!
//! ## Bounds
//!
//! Inherited whole from [`crate::recent_rule_addresses::RecentRuleAddressIndex`]
//! — capped, time-limited, in memory, never persisted.

use std::net::Ipv4Addr;
use std::sync::{Arc, OnceLock};

use crate::recent_rule_addresses::RecentRuleAddressIndex;

/// Address to the rule-less hostname that most recently resolved to it.
#[derive(Default)]
pub struct ObservedHostNames(RecentRuleAddressIndex);

impl ObservedHostNames {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Remember every address `hostname` just resolved to.
    pub fn record(&self, hostname: &str, addresses: &[Ipv4Addr]) {
        self.0.record(hostname, addresses);
    }

    /// The hostname `ip` was last seen resolving to, while that is still fresh.
    #[must_use]
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<String> {
        self.0.lookup(ip)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

static GLOBAL_OBSERVED_HOST_NAMES: OnceLock<Arc<ObservedHostNames>> = OnceLock::new();

/// Process-wide index. One per service run, shared by the DNS observation
/// consumer that fills it and the connection observer that reads it. Tests
/// construct [`ObservedHostNames`] directly and never touch this.
pub fn global_observed_host_names() -> Arc<ObservedHostNames> {
    Arc::clone(GLOBAL_OBSERVED_HOST_NAMES.get_or_init(|| Arc::new(ObservedHostNames::new())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recorded_host_is_found_by_any_of_its_addresses() {
        let idx = ObservedHostNames::new();
        let a = Ipv4Addr::new(23, 10, 20, 144);
        let b = Ipv4Addr::new(23, 10, 20, 145);
        assert!(idx.is_empty());
        idx.record("forum.talk.example", &[a, b]);
        assert_eq!(idx.lookup(a).as_deref(), Some("forum.talk.example"));
        assert_eq!(idx.lookup(b).as_deref(), Some("forum.talk.example"));
        assert_eq!(idx.len(), 2);
        assert_eq!(idx.lookup(Ipv4Addr::new(1, 1, 1, 1)), None);
    }

    #[test]
    fn an_empty_name_or_address_list_records_nothing() {
        let idx = ObservedHostNames::new();
        idx.record("", &[Ipv4Addr::new(1, 2, 3, 4)]);
        idx.record("host.example", &[]);
        assert!(idx.is_empty());
    }
}
