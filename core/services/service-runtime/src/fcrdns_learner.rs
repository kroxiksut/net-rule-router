//! FCrDNS reverse-learning for block-all.
//!
//! Under armed "block all unresolved" (Mode A block-all), a destination the
//! browser reached from its OWN in-process cache / DoH / a reused connection
//! never produced an OS-level DNS query, so the observer never saw the name and
//! the zone rule never expanded to it — the connection is dropped even though a
//! rule would have permitted it (the DoH blind-spot case). This module closes
//! that class by learning the name FROM THE DROP:
//!
//! ```text
//! NRR-dropped IP  →  PTR lookup  →  candidate name(s)
//!                 →  forward A of each name  →  keep only if the dropped IP is
//!                    in the answer (Forward-Confirmed reverse DNS)
//!                 →  feed the confirmed (name, IPs) through the SAME keep-logic
//!                    as an observed DNS fact (rules/SID gate, cache upsert)
//!                 →  next reconcile compiles the permit  →  retry succeeds.
//! ```
//!
//! **Why forward-confirm is mandatory (anti-spoofing).** An attacker controls
//! the PTR zone of their OWN IP, so a bare PTR answer could claim any name
//! (`bank.example`) and earn a permit. FCrDNS defeats this: the attacker does
//! NOT control the forward (`A`) zone of `bank.example`, so the lookup of the
//! claimed name will not return the attacker's IP, and the claim is rejected.
//! Only a name whose forward record actually contains the dropped IP is trusted.
//!
//! This is deliberately narrower and safer than the disabled reactive VPN
//! self-learning: it never grants a blanket exemption, it only feeds
//! the normal rule-gated cache path, and every learned fact is one a legitimate
//! DNS query would have produced anyway.
//!
//! Mechanism-free by construction: the reverse/forward resolver and the
//! confirmed-fact sink are injected as traits; the production wiring reuses the
//! raw-UDP transport and [`crate::dns_observation_consumer`] keep-logic.

use crate::bounded_set::BoundedRecentSet;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Reverse + forward DNS lookups for FCrDNS confirmation. The production impl
/// (wiring slice) reuses the captured-upstream raw-UDP transport; both calls are
/// best-effort and return empty on any failure (NXDOMAIN, timeout, malformed).
pub trait ReverseDnsResolver: Send + Sync {
    /// PTR lookup for `ip` → candidate hostnames (lower-cased, no trailing dot).
    fn resolve_ptr(&self, ip: Ipv4Addr) -> Vec<String>;
    /// Forward `A` lookup for `hostname` → its IPv4 addresses.
    fn resolve_a(&self, hostname: &str) -> Vec<Ipv4Addr>;
}

/// Sink for an FCrDNS-confirmed `(hostname, addresses)` fact. The production impl
/// feeds a synthetic DNS observation into [`crate::dns_observation_consumer`], so
/// the identical keep-logic runs (only rule-matching hosts for the active SID are
/// cached; non-rule names are dropped; collateral is accounted). Returns `true`
/// when the fact was kept (i.e. the host matched a rule and was cached).
pub trait ConfirmedHostSink: Send + Sync {
    fn record_confirmed(&self, hostname: &str, addresses: &[Ipv4Addr]) -> bool;

    /// A forward-confirmed name that matched NO rule (so
    /// [`Self::record_confirmed`] refused it) is a POSITIVELY-direct
    /// destination: the name provably owns the dropped IP, and no rule routes
    /// it to the secondary. The production impl registers its addresses in the
    /// known-direct registry so the block-all stops cutting it (a plain
    /// primary-path site the resolver never saw because the browser resolved
    /// it over DoH). Default `false` = direct-learning off
    /// (existing sinks/tests keep the strict behaviour).
    fn record_confirmed_direct(&self, _hostname: &str, _addresses: &[Ipv4Addr]) -> bool {
        false
    }
}

/// Outcome of one learn attempt (for the caller's summary/log).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LearnOutcome {
    /// A forward-confirmed, rule-matching name was cached.
    Learned,
    /// A forward-confirmed name matched NO rule and was
    /// registered as a known-DIRECT destination (block-all exemption).
    LearnedDirect,
    /// PTR/forward produced no name the dropped IP could be confirmed against,
    /// or no sink kept a confirmed name — nothing recorded.
    NotConfirmed,
    /// The IP was already attempted this session (deduped) or the per-session
    /// cap was reached — no lookup performed.
    Skipped,
}

/// FCrDNS learner: forward-confirms an NRR-dropped IP into a rule-gated cache
/// entry. Bounds its own cost with per-IP dedup (each dropped IP is attempted at
/// most once per session) and a hard per-session attempt cap, so a flood of
/// block-all drops cannot turn into an unbounded PTR/A query storm.
pub struct ReverseDnsLearner<R: ReverseDnsResolver, S: ConfirmedHostSink> {
    resolver: R,
    sink: S,
    /// IPs already attempted, bounded and least-recently-seen first.
    ///
    /// This used to be an unbounded set plus a hard per-session ceiling: once
    /// the ceiling was reached the learner stopped learning until the service
    /// restarted, and an address attempted once during a blip was never retried
    /// at all. Bounding the memory does both jobs — it caps what a drop storm
    /// can cost in memory, and an address that falls out of the window becomes
    /// learnable again, which is how a transient failure heals.
    attempted: Mutex<BoundedRecentSet<Ipv4Addr>>,
    /// When a lookup for an address came back with nothing at all. Such an
    /// attempt still dedups a drop storm, but only for
    /// [`FAILED_LOOKUP_RETRY_AFTER`] — a PTR that did not answer is most often
    /// the block-all that caused the drop, and remembering it as failed forever
    /// disabled learning for that address until the service restarted.
    failed_at: Mutex<HashMap<Ipv4Addr, Instant>>,
    remembered_attempts: usize,
}

/// How long a lookup that answered nothing suppresses the next attempt.
const FAILED_LOOKUP_RETRY_AFTER: Duration = Duration::from_secs(60);

impl<R: ReverseDnsResolver, S: ConfirmedHostSink> ReverseDnsLearner<R, S> {
    /// `remembered_attempts` bounds how many distinct destinations the learner
    /// keeps in mind at once.
    pub fn new(resolver: R, sink: S, remembered_attempts: usize) -> Self {
        Self {
            resolver,
            sink,
            attempted: Mutex::new(BoundedRecentSet::new(remembered_attempts)),
            failed_at: Mutex::new(HashMap::new()),
            remembered_attempts,
        }
    }

    /// May an address that is already in the window be tried again? Only if its
    /// last attempt learned nothing at all and the retry delay has passed.
    fn retry_is_due(&self, ip: Ipv4Addr) -> bool {
        let mut failed = self.failed_at.lock().unwrap_or_else(|p| p.into_inner());
        match failed.get(&ip) {
            Some(at) if at.elapsed() >= FAILED_LOOKUP_RETRY_AFTER => {
                failed.remove(&ip);
                true
            }
            _ => false,
        }
    }

    fn note_failed_lookup(&self, ip: Ipv4Addr) {
        let mut failed = self.failed_at.lock().unwrap_or_else(|p| p.into_inner());
        if failed.len() > self.remembered_attempts {
            failed.retain(|_, at| at.elapsed() < FAILED_LOOKUP_RETRY_AFTER);
        }
        failed.insert(ip, Instant::now());
    }

    /// Attempt to learn the name behind one NRR-dropped destination `ip`. Pure of
    /// policy — the caller has already established this was OUR block-all drop of
    /// a routable V4 remote. Idempotent per IP.
    pub fn learn(&self, ip: Ipv4Addr) -> LearnOutcome {
        self.learn_scoped(ip, true)
    }

    /// As [`Self::learn`], but `allow_direct == false` forbids the
    /// positively-direct classification. Set it when the drop was OUR
    /// app-scoped block of a process the user routed through the secondary:
    /// that block is the policy working, not a blind spot, and its destination
    /// is no evidence that anything reaches the address directly. Exempting it
    /// would let the routed app out over the primary the moment the tunnel
    /// blinks. Naming the address into a RULE host stays allowed — that is a
    /// permit for traffic that was already supposed to flow.
    pub fn learn_scoped(&self, ip: Ipv4Addr, allow_direct: bool) -> LearnOutcome {
        {
            let mut seen = self.attempted.lock().unwrap_or_else(|p| p.into_inner());
            if seen.contains(&ip) && !self.retry_is_due(ip) {
                return LearnOutcome::Skipped;
            }
            seen.observe(ip);
        }

        let names = self.resolver.resolve_ptr(ip);
        if names.is_empty() {
            // Nothing learned and nothing refuted. The attempt still dedups a
            // drop storm, but it must expire: a PTR that did not answer is
            // most often the block-all that caused this very drop, and a
            // permanent record disabled the address until the next restart.
            self.note_failed_lookup(ip);
            return LearnOutcome::NotConfirmed;
        }
        // Two passes so a rule-matching PTR name always wins over a direct
        // classification when an IP carries several confirmed names.
        let mut confirmed: Vec<String> = Vec::new();
        for name in names {
            // A machine name spelled out of the address itself forward-confirms
            // like any other, but names the operator's host rather than a
            // service — a wide rule over the provider's zone would otherwise
            // adopt its whole fleet. It still counts as evidence of a DIRECT
            // destination, which claims nothing about ownership.
            let address_derived = nrr_domain::ptr_names::is_address_derived(&name, ip);
            let forward = self.resolver.resolve_a(&name);
            // Forward-Confirmed reverse DNS: trust the name ONLY if its forward
            // record actually contains the dropped IP (see module anti-spoofing).
            if !forward.contains(&ip) {
                continue;
            }
            // ONLY the dropped address is forward-confirmed. The rest of the
            // `A` answer is whatever the zone's owner chose to return, and this
            // path feeds routes, pins and kill-switch exemptions — handing it
            // the whole set would let anyone who controls a PTR record and a
            // zone move addresses that were never confirmed to belong to the
            // name. The name's other addresses arrive the ordinary way, through
            // the resolver that confirms answers against a second source.
            if !address_derived && self.sink.record_confirmed(&name, &[ip]) {
                return LearnOutcome::Learned;
            }
            confirmed.push(name);
        }
        // Every confirmed name was refused by the rule gate, so the
        // destination is positively direct; register it as such.
        if !allow_direct {
            return LearnOutcome::NotConfirmed;
        }
        for name in confirmed {
            if self.sink.record_confirmed_direct(&name, &[ip]) {
                return LearnOutcome::LearnedDirect;
            }
        }
        LearnOutcome::NotConfirmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct FakeResolver {
        ptr: HashMap<Ipv4Addr, Vec<String>>,
        fwd: HashMap<String, Vec<Ipv4Addr>>,
    }
    impl ReverseDnsResolver for FakeResolver {
        fn resolve_ptr(&self, ip: Ipv4Addr) -> Vec<String> {
            self.ptr.get(&ip).cloned().unwrap_or_default()
        }
        fn resolve_a(&self, hostname: &str) -> Vec<Ipv4Addr> {
            self.fwd.get(hostname).cloned().unwrap_or_default()
        }
    }

    /// Sink that keeps a name only if it ends with a "rule" suffix, recording it.
    struct RuleSink {
        rule_suffix: String,
        kept: Mutex<Vec<String>>,
        kept_addresses: Mutex<Vec<Ipv4Addr>>,
    }
    impl ConfirmedHostSink for RuleSink {
        fn record_confirmed(&self, hostname: &str, addresses: &[Ipv4Addr]) -> bool {
            if hostname.ends_with(&self.rule_suffix) {
                self.kept
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(hostname.to_string());
                self.kept_addresses
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .extend_from_slice(addresses);
                true
            } else {
                false
            }
        }
    }

    fn learner(
        ptr: &[(Ipv4Addr, &[&str])],
        fwd: &[(&str, &[Ipv4Addr])],
        rule_suffix: &str,
        cap: usize,
    ) -> ReverseDnsLearner<FakeResolver, RuleSink> {
        let resolver = FakeResolver {
            ptr: ptr
                .iter()
                .map(|(ip, ns)| (*ip, ns.iter().map(|s| s.to_string()).collect()))
                .collect(),
            fwd: fwd
                .iter()
                .map(|(h, ips)| (h.to_string(), ips.to_vec()))
                .collect(),
        };
        let sink = RuleSink {
            rule_suffix: rule_suffix.to_string(),
            kept: Mutex::new(Vec::new()),
            kept_addresses: Mutex::new(Vec::new()),
        };
        ReverseDnsLearner::new(resolver, sink, cap)
    }

    #[test]
    fn learns_a_forward_confirmed_rule_host() {
        let ip = Ipv4Addr::new(203, 0, 113, 100); // a plain service host
        let l = learner(
            &[(ip, &["feed.example"])],
            &[("feed.example", &[ip])],
            ".example",
            64,
        );
        assert_eq!(l.learn(ip), LearnOutcome::Learned);
        assert_eq!(
            l.sink.kept.lock().unwrap().as_slice(),
            &["feed.example".to_string()]
        );
    }

    #[test]
    fn rejects_ptr_name_that_forward_does_not_confirm() {
        // Attacker's PTR claims bank.example, but its forward record does
        // NOT contain the attacker IP → rejected (anti-spoofing).
        let attacker = Ipv4Addr::new(203, 0, 113, 66);
        let l = learner(
            &[(attacker, &["bank.example"])],
            &[("bank.example", &[Ipv4Addr::new(198, 51, 100, 5)])],
            ".example",
            64,
        );
        assert_eq!(l.learn(attacker), LearnOutcome::NotConfirmed);
        assert!(l.sink.kept.lock().unwrap().is_empty());
    }

    #[test]
    fn a_machine_name_spelled_from_the_address_never_becomes_a_rule_host() {
        // The provider's generated reverse name forward-confirms perfectly and
        // sits under a wide rule — adopting it would hand the whole fleet to
        // that rule.
        let ip = Ipv4Addr::new(23, 10, 20, 132);
        let name = "132.20.10.23.bc.hosting.example";
        let l = learner(&[(ip, &[name])], &[(name, &[ip])], "hosting.example", 64);
        assert_eq!(l.learn(ip), LearnOutcome::NotConfirmed);
        assert!(l.sink.kept.lock().unwrap().is_empty());
    }

    #[test]
    fn a_service_name_under_the_same_zone_is_still_learned() {
        let ip = Ipv4Addr::new(23, 10, 20, 148);
        let name = "lh3.hosting.example";
        let l = learner(&[(ip, &[name])], &[(name, &[ip])], "hosting.example", 64);
        assert_eq!(l.learn(ip), LearnOutcome::Learned);
    }

    #[test]
    fn confirmed_but_non_rule_host_is_not_kept() {
        let ip = Ipv4Addr::new(23, 10, 20, 138);
        let l = learner(
            &[(ip, &["example.com"])],
            &[("example.com", &[ip])],
            ".example", // example.com is not a rule host
            64,
        );
        // Default sink has direct-learning off → still NotConfirmed.
        assert_eq!(l.learn(ip), LearnOutcome::NotConfirmed);
    }

    // ── Direct-learning ────────────────────────────────────────────────────────

    /// Sink with direct-learning ON: rule names by suffix, everything else
    /// confirmed lands in `direct`.
    struct DirectAwareSink {
        rule_suffix: String,
        kept: Mutex<Vec<String>>,
        direct: Mutex<Vec<String>>,
    }
    impl ConfirmedHostSink for DirectAwareSink {
        fn record_confirmed(&self, hostname: &str, _addresses: &[Ipv4Addr]) -> bool {
            if hostname.ends_with(&self.rule_suffix) {
                self.kept
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(hostname.to_string());
                true
            } else {
                false
            }
        }
        fn record_confirmed_direct(&self, hostname: &str, _addresses: &[Ipv4Addr]) -> bool {
            self.direct
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(hostname.to_string());
            true
        }
    }

    fn direct_learner(
        ptr: &[(Ipv4Addr, &[&str])],
        fwd: &[(&str, &[Ipv4Addr])],
        rule_suffix: &str,
    ) -> ReverseDnsLearner<FakeResolver, DirectAwareSink> {
        let resolver = FakeResolver {
            ptr: ptr
                .iter()
                .map(|(ip, ns)| (*ip, ns.iter().map(|s| s.to_string()).collect()))
                .collect(),
            fwd: fwd
                .iter()
                .map(|(h, ips)| (h.to_string(), ips.to_vec()))
                .collect(),
        };
        let sink = DirectAwareSink {
            rule_suffix: rule_suffix.to_string(),
            kept: Mutex::new(Vec::new()),
            direct: Mutex::new(Vec::new()),
        };
        ReverseDnsLearner::new(resolver, sink, 64)
    }

    #[test]
    fn confirmed_non_rule_host_is_learned_direct() {
        // Forward-confirmed, matches no rule → known-direct.
        let ip = Ipv4Addr::new(203, 0, 113, 68);
        let l = direct_learner(&[(ip, &["blog.test"])], &[("blog.test", &[ip])], ".example");
        assert_eq!(l.learn(ip), LearnOutcome::LearnedDirect);
        assert_eq!(
            l.sink.direct.lock().unwrap().as_slice(),
            &["blog.test".to_string()]
        );
        assert!(l.sink.kept.lock().unwrap().is_empty());
    }

    #[test]
    fn app_scoped_drop_never_learns_a_direct_host() {
        // The routed app was blocked because its tunnel is down. Calling its
        // destination direct would exempt that address from the block-all.
        let ip = Ipv4Addr::new(203, 0, 113, 68);
        let l = direct_learner(&[(ip, &["blog.test"])], &[("blog.test", &[ip])], ".example");
        assert_eq!(l.learn_scoped(ip, false), LearnOutcome::NotConfirmed);
        assert!(l.sink.direct.lock().unwrap().is_empty());
    }

    #[test]
    fn rule_name_wins_over_direct_when_ip_carries_both() {
        // One IP, two confirmed names: the rule host must be learned as a rule
        // host — direct classification only applies when EVERY confirmed name
        // failed the rule gate.
        let ip = Ipv4Addr::new(203, 0, 113, 100);
        let l = direct_learner(
            &[(ip, &["cdn.test", "feed.example"])],
            &[("cdn.test", &[ip]), ("feed.example", &[ip])],
            ".example",
        );
        assert_eq!(l.learn(ip), LearnOutcome::Learned);
        assert!(l.sink.direct.lock().unwrap().is_empty());
    }

    #[test]
    fn unconfirmed_name_is_never_learned_direct() {
        // Anti-spoofing carries over: a PTR claim whose forward record does not
        // contain the dropped IP earns NO direct exemption either.
        let attacker = Ipv4Addr::new(203, 0, 113, 66);
        let l = direct_learner(
            &[(attacker, &["blog.test"])],
            &[("blog.test", &[Ipv4Addr::new(203, 0, 113, 68)])],
            ".example",
        );
        assert_eq!(l.learn(attacker), LearnOutcome::NotConfirmed);
        assert!(l.sink.direct.lock().unwrap().is_empty());
    }

    #[test]
    fn second_attempt_on_same_ip_is_skipped() {
        let ip = Ipv4Addr::new(203, 0, 113, 100);
        let l = learner(
            &[(ip, &["feed.example"])],
            &[("feed.example", &[ip])],
            ".example",
            64,
        );
        assert_eq!(l.learn(ip), LearnOutcome::Learned);
        assert_eq!(l.learn(ip), LearnOutcome::Skipped, "deduped per IP");
    }

    #[test]
    fn the_window_evicts_instead_of_stopping_the_learner() {
        // The cap used to stop learning for the rest of the session: after N
        // distinct destinations nothing new was ever attempted, and an address
        // tried once during a blip was never retried. Now the memory is a
        // window - a new destination is always attempted, and one that falls
        // out of the window can be tried again, which is how a transient
        // failure heals.
        let a = Ipv4Addr::new(1, 1, 1, 1);
        let b = Ipv4Addr::new(2, 2, 2, 2);
        let l = learner(&[], &[], ".example", 1);
        assert_eq!(l.learn(a), LearnOutcome::NotConfirmed);
        assert_eq!(
            l.learn(b),
            LearnOutcome::NotConfirmed,
            "a new destination is still attempted once the window is full",
        );
        assert_eq!(
            l.learn(a),
            LearnOutcome::NotConfirmed,
            "and the evicted one is attempted again rather than remembered as failed forever",
        );
    }

    #[test]
    fn only_the_dropped_address_reaches_the_sink() {
        // Forward-confirmation proves ONE thing: that the name owns the address
        // we dropped. The rest of the `A` answer is whatever the zone's owner
        // chose to return, and this path feeds routes, pins and kill-switch
        // exemptions.
        let ip = Ipv4Addr::new(203, 0, 113, 100);
        let stranger = Ipv4Addr::new(203, 0, 113, 7);
        let l = learner(
            &[(ip, &["feed.example"])],
            &[("feed.example", &[ip, stranger])],
            ".example",
            64,
        );
        assert_eq!(l.learn(ip), LearnOutcome::Learned);
        assert_eq!(
            l.sink
                .kept_addresses
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .as_slice(),
            &[ip],
            "an unconfirmed address from the same answer must not be adopted"
        );
    }

    #[test]
    fn a_lookup_that_answered_nothing_is_retried_once_the_delay_passes() {
        // The failure most likely to happen here is the block-all that caused
        // the drop; a permanent record would disable the address until restart.
        let ip = Ipv4Addr::new(1, 1, 1, 1);
        let l = learner(&[], &[], ".example", 8);
        assert_eq!(l.learn(ip), LearnOutcome::NotConfirmed);
        assert_eq!(l.learn(ip), LearnOutcome::Skipped, "still deduped");

        // Age the record instead of sleeping out the delay.
        {
            let mut failed = l.failed_at.lock().unwrap_or_else(|p| p.into_inner());
            let stale = Instant::now()
                .checked_sub(FAILED_LOOKUP_RETRY_AFTER + Duration::from_secs(1))
                .expect("monotonic clock past the delay");
            failed.insert(ip, stale);
        }
        assert_eq!(
            l.learn(ip),
            LearnOutcome::NotConfirmed,
            "past the delay the address is attempted again"
        );
    }

    #[test]
    fn a_remembered_attempt_is_not_repeated() {
        // The window is still a dedup: while an address is in it, a drop storm
        // against the same destination costs one lookup, not one per packet.
        let a = Ipv4Addr::new(1, 1, 1, 1);
        let l = learner(&[], &[], ".example", 8);
        assert_eq!(l.learn(a), LearnOutcome::NotConfirmed);
        assert_eq!(l.learn(a), LearnOutcome::Skipped);
    }

    #[test]
    fn tries_multiple_ptr_names_until_one_confirms() {
        let ip = Ipv4Addr::new(203, 0, 113, 100);
        let l = learner(
            &[(ip, &["decoy.test", "feed.example"])],
            &[
                ("decoy.test", &[Ipv4Addr::new(9, 9, 9, 9)]),
                ("feed.example", &[ip]),
            ],
            ".example",
            64,
        );
        assert_eq!(l.learn(ip), LearnOutcome::Learned);
    }
}
