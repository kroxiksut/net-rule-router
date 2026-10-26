//! Virtual addresses of hosts no served user's rules name any more go back to
//! the pool once idle.
//!
//! The packet loop only hands over which addresses its flows are on, now and
//! then; the rule checks and the releases run on the fake-IP watchdog tick, so
//! no packet waits on them.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nrr_platform_api::fake_ip::FakeIpAllocator;

/// Whether a hostname still deserves its virtual address: a served user's rule
/// names it, or the direct-host rescue holds it.
pub type BindingKeeper = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// What names a host for [`BindingReleaser`]: a secondary rule of any served
/// user, paused ones included. A paused user's flows already take the main
/// link, and their hosts keep their addresses for when they resume; a user
/// who is no longer served names nothing.
pub fn rule_host_keeper(
    rules: Arc<dyn crate::per_sid_orchestrator::RulesProvider>,
    active_sid: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    served: crate::dns_resolver_ports::ResolverPrincipalsFn,
) -> Arc<dyn Fn(&str) -> bool + Send + Sync> {
    keeper_over(served_oracle(rules, active_sid, served))
}

/// Deliberately without the pause: the DNS answerer's oracle skips paused
/// users, this one must not.
fn served_oracle(
    rules: Arc<dyn crate::per_sid_orchestrator::RulesProvider>,
    active_sid: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    served: crate::dns_resolver_ports::ResolverPrincipalsFn,
) -> crate::dns_resolver_ports::ActiveRuleHostOracle {
    crate::dns_resolver_ports::ActiveRuleHostOracle::new(rules, active_sid).with_served(served)
}

fn keeper_over(
    oracle: crate::dns_resolver_ports::ActiveRuleHostOracle,
) -> Arc<dyn Fn(&str) -> bool + Send + Sync> {
    use crate::dns_resolver::RuleHostOracle as _;
    Arc::new(move |hostname| oracle.is_rule_host(hostname))
}

/// Bindings judged per run; the rest wait for the next tick.
const RELEASE_BUDGET_PER_RUN: usize = 256;

/// The addresses the stack's flows were on when it last said, and the book
/// stamp it saw then.
#[derive(Debug, Default, Clone)]
struct LiveSnapshot {
    addresses: Vec<IpAddr>,
    policy_stamp: u64,
}

/// The packet loop's hand-over: written by the stack, read by the releaser.
#[derive(Debug, Default)]
pub struct LiveFlowAddresses {
    latest: Mutex<LiveSnapshot>,
}

impl LiveFlowAddresses {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace what the stack last reported.
    pub fn publish(&self, addresses: Vec<IpAddr>, policy_stamp: u64) {
        *self.latest.lock().unwrap_or_else(|p| p.into_inner()) = LiveSnapshot {
            addresses,
            policy_stamp,
        };
    }

    fn latest(&self) -> LiveSnapshot {
        self.latest
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

#[derive(Debug, Default)]
struct ReleaseCursor {
    /// Bindings up to here in the recycling order were judged under `stamp`.
    checked_upto: u64,
    stamp: u64,
}

/// Releases the bindings [`BindingKeeper`] no longer wants once idle, never
/// one a flow is on.
pub struct BindingReleaser {
    allocator: Arc<Mutex<FakeIpAllocator>>,
    keep: BindingKeeper,
    live: Arc<LiveFlowAddresses>,
    idle: Duration,
    cursor: Mutex<ReleaseCursor>,
}

impl BindingReleaser {
    #[must_use]
    pub fn new(
        allocator: Arc<Mutex<FakeIpAllocator>>,
        keep: BindingKeeper,
        live: Arc<LiveFlowAddresses>,
    ) -> Self {
        Self {
            allocator,
            keep,
            live,
            idle: nrr_platform_api::fake_ip::allocator::RECYCLE_MIN_IDLE,
            cursor: Mutex::new(ReleaseCursor::default()),
        }
    }

    /// Shorten the idle window so a test need not wait ten minutes.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_idle(mut self, idle: Duration) -> Self {
        self.idle = idle;
        self
    }

    /// One pass; returns how many bindings went back to the pool. The
    /// addresses flows are on are marked used first, so neither this nor the
    /// pool's recycling takes them; the map is locked only to read and to
    /// release, never while the keeper is asked.
    pub fn run_once(&self) -> usize {
        let live = self.live.latest();
        let mut cursor = self.cursor.lock().unwrap_or_else(|p| p.into_inner());
        // A moved book may have dropped hosts judged under the old one.
        if cursor.stamp != live.policy_stamp {
            cursor.stamp = live.policy_stamp;
            cursor.checked_upto = 0;
        }
        let idle = {
            let mut map = self.allocator.lock().unwrap_or_else(|p| p.into_inner());
            for ip in &live.addresses {
                map.touch_address(*ip);
            }
            map.idle_bindings(cursor.checked_upto, self.idle, RELEASE_BUDGET_PER_RUN)
        };
        let on_flow: HashSet<IpAddr> = live.addresses.iter().copied().collect();
        let mut released = 0;
        for found in idle {
            cursor.checked_upto = found.order;
            let held = on_flow.contains(&IpAddr::V4(found.binding.v4))
                || found
                    .binding
                    .v6
                    .is_some_and(|v6| on_flow.contains(&IpAddr::V6(v6)));
            if held || (self.keep)(&found.domain) {
                continue;
            }
            if self
                .allocator
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .release_if_untouched(&found.domain, found.order)
            {
                released += 1;
            }
        }
        if released > 0 {
            tracing::debug!(
                target: "nrr::fake-ip",
                released,
                "released the virtual addresses of hosts no rule names any more",
            );
        }
        released
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    const GONE: &str = "gone.example";
    const STAYING: &str = "staying.example";

    fn allocator_with(hosts: &[&str]) -> Arc<Mutex<FakeIpAllocator>> {
        let mut allocator = FakeIpAllocator::default();
        for host in hosts {
            allocator.allocate(host).expect("allocate");
        }
        Arc::new(Mutex::new(allocator))
    }

    fn bound(allocator: &Arc<Mutex<FakeIpAllocator>>, host: &str) -> Option<std::net::Ipv4Addr> {
        allocator
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .binding_for_domain(host)
            .map(|b| b.v4)
    }

    /// The hosts some book names; dropping one moves the stamp, as an
    /// activation does.
    #[derive(Default)]
    struct Book {
        hosts: Mutex<HashSet<String>>,
        stamp: AtomicU64,
    }

    impl Book {
        fn with(hosts: &[&str]) -> Arc<Self> {
            let book = Self::default();
            book.hosts
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .extend(hosts.iter().map(|h| (*h).to_owned()));
            Arc::new(book)
        }

        fn remove(&self, host: &str) {
            self.hosts
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(host);
            self.stamp.fetch_add(1, Ordering::SeqCst);
        }

        fn keeper(self: &Arc<Self>) -> BindingKeeper {
            let book = Arc::clone(self);
            Arc::new(move |host: &str| {
                book.hosts
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .contains(host)
            })
        }
    }

    fn releaser(
        allocator: &Arc<Mutex<FakeIpAllocator>>,
        book: &Arc<Book>,
        live: &Arc<LiveFlowAddresses>,
        idle: Duration,
    ) -> BindingReleaser {
        BindingReleaser::new(Arc::clone(allocator), book.keeper(), Arc::clone(live)).with_idle(idle)
    }

    /// A host taken out of the rules used to keep its virtual address (and its
    /// stored row) until the pool ran out; once idle it goes back, while a host
    /// the rules still name keeps its own.
    #[test]
    fn a_host_removed_from_the_rules_frees_its_address_once_idle() {
        let allocator = allocator_with(&[GONE, STAYING]);
        let book = Book::with(&[GONE, STAYING]);
        let live = Arc::new(LiveFlowAddresses::new());
        let staying = bound(&allocator, STAYING);
        let releaser = releaser(&allocator, &book, &live, Duration::ZERO);
        assert_eq!(releaser.run_once(), 0, "both still named");

        book.remove(GONE);
        live.publish(Vec::new(), book.stamp.load(Ordering::SeqCst));
        assert_eq!(releaser.run_once(), 1);
        assert_eq!(bound(&allocator, GONE), None);
        assert_eq!(bound(&allocator, STAYING), staying);
    }

    /// Within the idle window a host that left the rules keeps its address: an
    /// application may still hold it from the last answer.
    #[test]
    fn a_host_removed_from_the_rules_keeps_its_address_within_the_idle_window() {
        let allocator = allocator_with(&[GONE]);
        let book = Book::with(&[]);
        let live = Arc::new(LiveFlowAddresses::new());
        let releaser = releaser(&allocator, &book, &live, Duration::from_secs(600));
        assert_eq!(releaser.run_once(), 0);
        assert!(bound(&allocator, GONE).is_some());
    }

    // ── Whose rules keep a host: every served user's, paused or not ─────────

    const ALICE: &str = "S-1-5-21-1-1-1-1001";
    const BOB: &str = "S-1-5-21-1-1-1-1002";
    const BOBS_HOST: &str = "bob-site.example";

    /// Each user's secondary hosts; editable by the test.
    #[derive(Default)]
    struct Books(Mutex<std::collections::HashMap<String, Vec<String>>>);

    impl Books {
        fn set(&self, sid: &str, hosts: &[&str]) {
            self.0.lock().unwrap_or_else(|p| p.into_inner()).insert(
                sid.to_owned(),
                hosts.iter().map(|h| (*h).to_owned()).collect(),
            );
        }
    }

    impl crate::per_sid_orchestrator::RulesProvider for Books {
        fn active_rules(&self) -> Option<crate::per_sid_orchestrator::ActiveRulesSnapshot> {
            None
        }

        fn active_rules_for(
            &self,
            principal: &str,
        ) -> Option<crate::per_sid_orchestrator::ActiveRulesSnapshot> {
            use nrr_domain::canonical::{
                CanonicalAddressMatch, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet,
            };
            let books = self.0.lock().unwrap_or_else(|p| p.into_inner());
            let rules = books
                .get(principal)?
                .iter()
                .enumerate()
                .map(|(i, host)| CanonicalRule {
                    id: nrr_domain::RuleId(format!("r{i}")),
                    enabled: true,
                    address_match: Some(CanonicalAddressMatch::ExactFqdn(host.clone())),
                    app_match: None,
                    comment: String::new(),
                    action: nrr_domain::RuleAction::Route,
                    origin: None,
                })
                .collect();
            Some(crate::per_sid_orchestrator::ActiveRulesSnapshot {
                rule_book: CanonicalRuleBook {
                    primary: CanonicalRuleSet::from_rules(vec![]),
                    secondary: CanonicalRuleSet::from_rules(rules),
                },
            })
        }
    }

    /// Alice routes, Bob is served and has paused (the pause is nowhere in
    /// the keeper: that is the point); the books' stamp moves with every edit
    /// the test makes.
    fn bob_paused() -> (Arc<Books>, Arc<AtomicU64>, BindingKeeper) {
        let books = Arc::new(Books::default());
        books.set(BOB, &[BOBS_HOST]);
        let stamp = Arc::new(AtomicU64::new(1));
        let seen = Arc::clone(&stamp);
        let oracle = served_oracle(
            Arc::clone(&books) as Arc<dyn crate::per_sid_orchestrator::RulesProvider>,
            Arc::new(|| Some(ALICE.to_owned())),
            Arc::new(|| vec![ALICE.to_owned(), BOB.to_owned()]),
        )
        .with_books_stamp(Arc::new(move || seen.load(Ordering::SeqCst)));
        (books, stamp, keeper_over(oracle))
    }

    /// Bob paused routing for an hour. His hosts' virtual addresses used to go
    /// back to the pool after ten idle minutes, so the addresses his programs
    /// still held stopped working when he resumed.
    #[test]
    fn a_paused_users_rule_host_keeps_its_address_past_the_idle_window() {
        let (_books, _stamp, named) = bob_paused();
        let allocator = allocator_with(&[BOBS_HOST]);
        let releaser = BindingReleaser::new(
            Arc::clone(&allocator),
            named,
            Arc::new(LiveFlowAddresses::new()),
        )
        .with_idle(Duration::ZERO);
        assert_eq!(releaser.run_once(), 0);
        assert!(bound(&allocator, BOBS_HOST).is_some());
    }

    /// Removing the rule frees the address, paused or not.
    #[test]
    fn a_paused_users_host_is_released_once_the_rule_is_removed() {
        let (books, stamp, named) = bob_paused();
        assert!(!named("elsewhere.example"));
        books.set(BOB, &[]);
        stamp.fetch_add(1, Ordering::SeqCst);
        assert!(!named(BOBS_HOST), "no served user names it now");

        let allocator = allocator_with(&[BOBS_HOST]);
        let releaser = BindingReleaser::new(
            Arc::clone(&allocator),
            named,
            Arc::new(LiveFlowAddresses::new()),
        )
        .with_idle(Duration::ZERO);
        assert_eq!(releaser.run_once(), 1);
        assert_eq!(bound(&allocator, BOBS_HOST), None);
    }

    /// Bob signed out and is served no more: his rules name nothing.
    #[test]
    fn a_host_of_a_user_no_longer_served_is_released() {
        let books = Arc::new(Books::default());
        books.set(BOB, &[BOBS_HOST]);
        let named = rule_host_keeper(
            books as Arc<dyn crate::per_sid_orchestrator::RulesProvider>,
            Arc::new(|| Some(ALICE.to_owned())),
            Arc::new(|| vec![ALICE.to_owned()]),
        );
        let allocator = allocator_with(&[BOBS_HOST]);
        let releaser = BindingReleaser::new(
            Arc::clone(&allocator),
            named,
            Arc::new(LiveFlowAddresses::new()),
        )
        .with_idle(Duration::ZERO);
        assert_eq!(releaser.run_once(), 1);
    }

    /// A download that outlives its rule keeps its virtual address: freeing it
    /// would hand it to the next hostname asked.
    #[test]
    fn an_address_with_a_live_flow_is_not_freed_under_it() {
        let allocator = allocator_with(&[GONE]);
        let book = Book::with(&[]);
        let live = Arc::new(LiveFlowAddresses::new());
        let fake = bound(&allocator, GONE).expect("bound");
        live.publish(vec![IpAddr::V4(fake)], 0);
        let releaser = releaser(&allocator, &book, &live, Duration::ZERO);
        assert_eq!(releaser.run_once(), 0);
        assert_eq!(bound(&allocator, GONE), Some(fake));
    }
}
