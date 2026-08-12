//! Addresses we recently saw a rule hostname resolve to — including the ones
//! we chose NOT to answer with.
//!
//! ## Why
//!
//! A rule host behind a CDN answers with a rotating pool. The resolver answers
//! a small STABLE subset of it on purpose (see `dns_resolver`): the client then
//! only ever connects to the few addresses we enforce, instead of dragging the
//! provider's entire front-end pool into the enforcement set.
//!
//! An application that keeps its OWN address cache does not play along. A
//! browser that learned the full pool earlier — before the service came up,
//! from a previous session, or from address hints attached to a connection —
//! keeps rotating through addresses our answer never mentioned. Under a
//! block-everything-unmatched posture those connections are dropped, and the
//! user sees a site that "half works": the addresses we pinned succeed, the
//! rest fail.
//!
//! Naming the dropped address by reverse lookup solves only part of it: a
//! provider's reverse names often belong to infrastructure domains that match
//! no rule, so the confirmation never ties the address back to the rule host.
//!
//! This index closes that gap with what we already know for certain: the
//! address was in the very answer OUR resolver received for a rule hostname.
//! No lookup, no guessing — an exact-match memory of recent resolutions, so a
//! drop can be tied back to its hostname and the address enforced (permitted +
//! routed) on the next reconcile.
//!
//! ## Bounds
//!
//! In-memory, per service run, capped and time-limited: an entry older than
//! [`ENTRY_TTL`] is ignored (the pool has moved on), and the map never exceeds
//! [`MAX_ENTRIES`] — the oldest entries are evicted first. Nothing here is
//! persisted: a restart re-learns from the first resolution.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// How long a remembered address stays usable. Long enough to cover a browser
/// cycling through a pool it cached minutes ago, short enough that a pool the
/// provider has rotated away from stops being enforceable.
pub const ENTRY_TTL: Duration = Duration::from_secs(30 * 60);

/// Upper bound on remembered addresses. A busy rule set with several CDN-backed
/// hosts stays well under this; the cap only bounds pathological churn.
pub const MAX_ENTRIES: usize = 4096;

struct Entry {
    hostname: String,
    seen_at: Instant,
}

/// Address → the rule hostname that most recently resolved to it.
#[derive(Default)]
pub struct RecentRuleAddressIndex {
    inner: Mutex<HashMap<Ipv4Addr, Entry>>,
}

impl RecentRuleAddressIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Remember every address `hostname` just resolved to. Cheap enough to call
    /// on the resolver's hot path: one lock, a handful of inserts.
    pub fn record(&self, hostname: &str, addresses: &[Ipv4Addr]) {
        let _ = self.record_displacing(hostname, addresses);
    }

    /// [`record`](Self::record), reporting the hostname this answer completely
    /// displaced.
    ///
    /// `Some(other)` means EVERY address in `addresses` was, until this call,
    /// remembered for the single other hostname `other` — two names answered
    /// with one identical address set, the signature of an upstream handing out
    /// a stub instead of resolving. Partial overlap (the ordinary shared-CDN
    /// front end) reports nothing, and neither does a stale memory.
    pub fn record_displacing(&self, hostname: &str, addresses: &[Ipv4Addr]) -> Option<String> {
        if hostname.is_empty() || addresses.is_empty() {
            return None;
        }
        let now = Instant::now();
        let Ok(mut map) = self.inner.lock() else {
            return None;
        };
        let mut displaced: Option<String> = None;
        let mut every_address_displaced = true;
        for ip in addresses {
            let previous = map.insert(
                *ip,
                Entry {
                    hostname: hostname.to_string(),
                    seen_at: now,
                },
            );
            let prior =
                previous.filter(|e| e.hostname != hostname && e.seen_at.elapsed() < ENTRY_TTL);
            match (prior, &displaced) {
                (None, _) => every_address_displaced = false,
                (Some(e), None) => displaced = Some(e.hostname),
                // A second, different previous owner means the set is shared
                // rather than wholesale reassigned — not the shape we report.
                (Some(e), Some(seen)) if &e.hostname != seen => every_address_displaced = false,
                (Some(_), Some(_)) => {}
            }
        }
        if map.len() > MAX_ENTRIES {
            // Drop the stalest half in one pass rather than sorting the whole
            // map on every insert past the cap.
            let mut ages: Vec<(Ipv4Addr, Instant)> =
                map.iter().map(|(ip, e)| (*ip, e.seen_at)).collect();
            ages.sort_by_key(|(_, at)| *at);
            for (ip, _) in ages.into_iter().take(MAX_ENTRIES / 2) {
                map.remove(&ip);
            }
        }
        displaced.filter(|_| every_address_displaced)
    }

    /// The rule hostname `ip` was last seen resolving to, if that memory is
    /// still fresh. `None` once the entry has aged out.
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<String> {
        let map = self.inner.lock().ok()?;
        let entry = map.get(&ip)?;
        (entry.seen_at.elapsed() < ENTRY_TTL).then(|| entry.hostname.clone())
    }

    /// Number of remembered addresses (diagnostics / tests).
    pub fn len(&self) -> usize {
        self.inner.lock().map(|m| m.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

static GLOBAL_RECENT_RULE_ADDRESSES: OnceLock<Arc<RecentRuleAddressIndex>> = OnceLock::new();

/// Process-wide index. The resolver writes to it while answering; the
/// learn-from-drops worker reads it before falling back to a reverse lookup.
/// Tests construct [`RecentRuleAddressIndex`] directly and never touch this.
pub fn global_recent_rule_addresses() -> Arc<RecentRuleAddressIndex> {
    GLOBAL_RECENT_RULE_ADDRESSES
        .get_or_init(|| Arc::new(RecentRuleAddressIndex::new()))
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(d: u8) -> Ipv4Addr {
        Ipv4Addr::new(142, 251, 150, d)
    }

    #[test]
    fn remembers_every_resolved_address_not_just_the_answered_ones() {
        let idx = RecentRuleAddressIndex::new();
        idx.record("google.com", &[ip(1), ip(2), ip(3)]);

        assert_eq!(idx.lookup(ip(2)).as_deref(), Some("google.com"));
        assert_eq!(idx.lookup(ip(3)).as_deref(), Some("google.com"));
        assert!(idx.lookup(ip(9)).is_none());
    }

    #[test]
    fn last_writer_wins_when_two_hosts_share_an_address() {
        let idx = RecentRuleAddressIndex::new();
        idx.record("a.example", &[ip(1)]);
        idx.record("b.example", &[ip(1)]);

        assert_eq!(idx.lookup(ip(1)).as_deref(), Some("b.example"));
    }

    /// The  shape: one address pair handed to two unrelated names.
    #[test]
    fn reports_a_wholesale_owner_change() {
        let idx = RecentRuleAddressIndex::new();
        assert_eq!(idx.record_displacing("signal.me", &[ip(1), ip(2)]), None);
        assert_eq!(
            idx.record_displacing("chatgpt.com", &[ip(1), ip(2)])
                .as_deref(),
            Some("signal.me")
        );
    }

    #[test]
    fn partial_overlap_and_re_resolution_report_nothing() {
        let idx = RecentRuleAddressIndex::new();
        idx.record("a.example", &[ip(1), ip(2)]);
        // One address in common, one fresh — an ordinary shared front end.
        assert_eq!(idx.record_displacing("b.example", &[ip(2), ip(3)]), None);
        // Re-resolving the same host is never a collision.
        assert_eq!(idx.record_displacing("b.example", &[ip(2), ip(3)]), None);
    }

    #[test]
    fn two_different_previous_owners_report_nothing() {
        let idx = RecentRuleAddressIndex::new();
        idx.record("a.example", &[ip(1)]);
        idx.record("b.example", &[ip(2)]);
        assert_eq!(idx.record_displacing("c.example", &[ip(1), ip(2)]), None);
    }

    #[test]
    fn empty_inputs_are_ignored() {
        let idx = RecentRuleAddressIndex::new();
        idx.record("", &[ip(1)]);
        idx.record("google.com", &[]);

        assert!(idx.is_empty());
    }

    #[test]
    fn stays_under_the_cap() {
        let idx = RecentRuleAddressIndex::new();
        for chunk in 0..(MAX_ENTRIES / 128 + 2) {
            let ips: Vec<Ipv4Addr> = (0..128)
                .map(|i| Ipv4Addr::new(10, (chunk % 256) as u8, (i / 256) as u8, (i % 256) as u8))
                .collect();
            idx.record("host.example", &ips);
        }
        assert!(idx.len() <= MAX_ENTRIES, "len was {}", idx.len());
    }
}
