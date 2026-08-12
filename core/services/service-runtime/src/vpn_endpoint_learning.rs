//! In-memory, bounded set of VPN server IPs learned from role-verified
//! kill-switch drops (see [`crate::conn_observation_consumer`] and
//! [`crate::killswitch_drop_registry`]).
//!
//! Deliberately **not persisted**: the set is session-scoped and rebuilds
//! itself from the next handshake attempt if the service restarts, so a
//! stale or hostile entry can never outlive the process, let alone survive
//! a reboot. Bounded by [`CAP`] entries and [`ENTRY_TTL`] per entry so a
//! spoofed or transient "VPN-named" process cannot grow the exemption
//! surface without limit.

use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// Maximum distinct server IPs held at once. Oldest entry is evicted to make
/// room for a new one once the cap is reached.
const CAP: usize = 8;

/// How long a learned entry stays exempt without being re-observed.
const ENTRY_TTL: Duration = Duration::from_secs(6 * 60 * 60);

struct Entry {
    ip: Ipv4Addr,
    learned_at: SystemTime,
}

/// Bounded, TTL'd, in-memory set of learned VPN bootstrap server IPs.
#[derive(Default)]
pub struct LearnedVpnEndpoints {
    entries: Mutex<Vec<Entry>>,
}

impl LearnedVpnEndpoints {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `ip` as learned at `now`, pruning expired entries first.
    /// Returns `true` when `ip` is newly added; `false` when it was already
    /// present (its timestamp is refreshed either way). At capacity, the
    /// single oldest entry is evicted to admit the new one.
    pub fn register(&self, ip: Ipv4Addr, now: SystemTime) -> bool {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        prune_expired(&mut entries, now);
        if let Some(existing) = entries.iter_mut().find(|e| e.ip == ip) {
            existing.learned_at = now;
            return false;
        }
        if entries.len() >= CAP {
            if let Some((oldest_idx, _)) =
                entries.iter().enumerate().min_by_key(|(_, e)| e.learned_at)
            {
                entries.remove(oldest_idx);
            }
        }
        entries.push(Entry {
            ip,
            learned_at: now,
        });
        true
    }

    /// Currently-live learned server IPs as of `now` (expired entries
    /// pruned first). Order is not significant to callers — every consumer
    /// merges this into a destination set.
    pub fn current(&self, now: SystemTime) -> Vec<Ipv4Addr> {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        prune_expired(&mut entries, now);
        entries.iter().map(|e| e.ip).collect()
    }
}

/// Drop every entry whose TTL has elapsed as of `now`. An entry whose
/// `learned_at` is after `now` (clock stepped backward) is kept — never
/// treated as auto-expired.
fn prune_expired(entries: &mut Vec<Entry>, now: SystemTime) {
    entries.retain(|e| {
        now.duration_since(e.learned_at)
            .map(|elapsed| elapsed < ENTRY_TTL)
            .unwrap_or(true)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(d: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, d)
    }

    #[test]
    fn register_returns_true_for_new_ip_false_for_repeat() {
        let learned = LearnedVpnEndpoints::new();
        let now = SystemTime::now();
        assert!(learned.register(ip(1), now));
        assert!(!learned.register(ip(1), now));
        assert_eq!(learned.current(now), vec![ip(1)]);
    }

    #[test]
    fn current_prunes_entries_past_ttl() {
        let learned = LearnedVpnEndpoints::new();
        let t0 = SystemTime::now();
        learned.register(ip(1), t0);
        let still_fresh = t0 + ENTRY_TTL - Duration::from_secs(1);
        assert_eq!(learned.current(still_fresh), vec![ip(1)]);
        let expired = t0 + ENTRY_TTL + Duration::from_secs(1);
        assert!(learned.current(expired).is_empty());
    }

    #[test]
    fn cap_evicts_the_oldest_entry() {
        let learned = LearnedVpnEndpoints::new();
        let t0 = SystemTime::now();
        for i in 0..CAP as u8 {
            learned.register(ip(i), t0 + Duration::from_secs(i as u64));
        }
        // At capacity: the next distinct IP evicts ip(0), the oldest.
        let t_new = t0 + Duration::from_secs(CAP as u64 + 1);
        assert!(learned.register(ip(CAP as u8), t_new));
        let current = learned.current(t_new);
        assert_eq!(current.len(), CAP);
        assert!(!current.contains(&ip(0)));
        assert!(current.contains(&ip(CAP as u8)));
    }

    #[test]
    fn re_registering_refreshes_ttl_instead_of_duplicating() {
        let learned = LearnedVpnEndpoints::new();
        let t0 = SystemTime::now();
        learned.register(ip(1), t0);
        let just_before_expiry = t0 + ENTRY_TTL - Duration::from_secs(1);
        learned.register(ip(1), just_before_expiry);
        // Had the first timestamp not been refreshed this would be expired.
        let after_original_ttl = t0 + ENTRY_TTL + Duration::from_secs(1);
        assert_eq!(learned.current(after_original_ttl), vec![ip(1)]);
    }

    #[test]
    fn current_is_empty_when_nothing_registered() {
        let learned = LearnedVpnEndpoints::new();
        assert!(learned.current(SystemTime::now()).is_empty());
    }
}
