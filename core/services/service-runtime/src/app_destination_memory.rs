//! Cross-session memory of the destinations an application rule's process uses.
//!
//! ## The gap this closes
//!
//! An application routed over the additional link is pinned to that link for
//! EVERY destination: the enforcement layer emits one process-scoped permit that
//! only matches while the flow egresses the additional link, plus a block for
//! everything else. The only thing that can put one of the app's flows on that
//! link is a host route, and [`crate::route_codegen`] derives those exclusively
//! from addresses [`crate::app_observation_lookup`] has already seen. So the
//! app's first contact with a new address has no route, egresses the main link,
//! misses the permit and is refused — and that refusal is what teaches the
//! address, after which the route and the pin follow within a tick.
//!
//! The behaviour is correct: it never leaks, and it converges in milliseconds.
//! What is wasteful is that the observation set is in-memory, so **every session
//! relearns the same addresses the same way** — a messenger with a fixed set of
//! datacentre addresses paid one refusal per address per restart (observed at
//! roughly 190 addresses on a real session).
//!
//! ## What this module does
//!
//! Carries the observed set across restarts, so the route and the permit exist
//! BEFORE the first connection of the next session:
//!
//! - [`AppDestinationMemory::warm_load`] re-seeds the in-memory store from the
//!   state DB at start-up.
//! - [`AppDestinationMemory::flush`] writes back the destinations of the apps the
//!   rule book currently routes over the additional link, refreshing each one's
//!   confirmation time.
//!
//! ## Scope: it can never widen enforcement
//!
//! Only apps the **rule book** routes over the additional link are ever
//! persisted, and only their address-free route rules — the exact set
//! [`crate::route_codegen::generate_secondary_routes`] fans out. The codegen
//! iterates rules, not observations, so a destination remembered for an app
//! whose rule is later removed produces nothing at all; the rule-gated write
//! simply keeps the table from accumulating that dead weight in the first place.
//!
//! ## Freshness
//!
//! A remembered destination is evidence, not policy: the address was in use,
//! and the route it produces is not process-scoped, so a destination that has
//! since been recycled to another tenant would move that tenant's traffic — and,
//! under the leak guard, block it while the additional link is down. That is the
//! same failure the FQDN cache's confirmation window exists to prevent, so this
//! reader uses the SAME window
//! ([`crate::fqdn_cache_lookup::ENFORCEMENT_CONFIRMATION_WINDOW`]): one freshness
//! rule across every enforcement view, no second dial to reason about. A live
//! app refreshes its addresses on every flush, so the window only bites after the
//! app has genuinely stopped using one.
//!
//! Addresses the user typed into the rule set are the opposite case and need
//! nothing from this module: they are policy, not observation, and an `ExactIp`
//! rule already emits its own host route and permit with no cache in the path.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use nrr_domain::canonical::{CanonicalAppPattern, CanonicalRuleSet};
use nrr_domain::RuleAction;

use crate::app_observation_lookup::{AppObservationLookup, AppObservationStore};
use crate::fqdn_cache_lookup::ENFORCEMENT_CONFIRMATION_WINDOW;
use crate::per_sid_orchestrator::RulesProvider;
use crate::supervised_runtime::ActiveRoutingSidFn;
use crate::wfp_codegen::PER_HOSTNAME_IP_CAP;

/// Persist one application's currently-known destinations, stamped with the
/// confirmation time. The production impl writes
/// `nrr_storage::app_destinations::AppDestinationsRepository::upsert`.
pub type AppDestinationPersistFn = Arc<dyn Fn(&str, &[Ipv4Addr], SystemTime) + Send + Sync>;

/// Load every `(app pattern, destination)` pair confirmed at or after the given
/// instant. The production impl reads
/// `nrr_storage::app_destinations::AppDestinationsRepository::load_confirmed_since`
/// and prunes what falls outside it.
pub type AppDestinationLoadFn = Arc<dyn Fn(SystemTime) -> Vec<(String, Ipv4Addr)> + Send + Sync>;

/// Outcome of one [`AppDestinationMemory::flush`] pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FlushSummary {
    /// Applications whose destinations were written back.
    pub apps: u32,
    /// Destinations written back across those applications.
    pub destinations: u32,
}

impl FlushSummary {
    pub fn made_progress(&self) -> bool {
        self.destinations > 0
    }
}

/// Carries observed application destinations across service restarts.
pub struct AppDestinationMemory {
    observations: Arc<AppObservationStore>,
    rules: Arc<dyn RulesProvider>,
    active_sid: ActiveRoutingSidFn,
    persist: AppDestinationPersistFn,
    load: AppDestinationLoadFn,
    /// How recently a destination must have been confirmed to be re-seeded.
    /// See the module docs — this is the shared enforcement window, overridable
    /// only so tests can exercise the boundary without sleeping.
    window: Duration,
}

impl AppDestinationMemory {
    pub fn new(
        observations: Arc<AppObservationStore>,
        rules: Arc<dyn RulesProvider>,
        active_sid: ActiveRoutingSidFn,
        persist: AppDestinationPersistFn,
        load: AppDestinationLoadFn,
    ) -> Self {
        Self {
            observations,
            rules,
            active_sid,
            persist,
            load,
            window: ENFORCEMENT_CONFIRMATION_WINDOW,
        }
    }

    /// Override the confirmation window. Builder-style; every production call
    /// site keeps the shared [`ENFORCEMENT_CONFIRMATION_WINDOW`] default.
    pub fn with_confirmation_window(mut self, window: Duration) -> Self {
        self.window = window;
        self
    }

    /// Re-seed the in-memory observation store from the previous sessions,
    /// admitting only destinations confirmed inside the freshness window.
    /// Returns how many were admitted. Run once, before the first apply, so the
    /// routes exist ahead of the applications' first connections.
    pub fn warm_load(&self, now: SystemTime) -> usize {
        // A clock close enough to the epoch for the cutoff to underflow admits
        // everything: an unknown-age set is no worse than a cold one, and the
        // flush restamps it within a tick.
        let cutoff = now
            .checked_sub(self.window)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let pairs = (self.load)(cutoff);
        if pairs.is_empty() {
            return 0;
        }
        let seeded = self.observations.seed_many(&pairs);
        if seeded > 0 {
            tracing::info!(
                target: "nrr::app-routing",
                destinations = seeded,
                "pre-seeded application destinations from earlier sessions — their routes exist before the first connection",
            );
        }
        seeded
    }

    /// Write back the destinations of every application the active user's rule
    /// book routes over the additional link, restamping each one's confirmation
    /// time. Cheap and self-limiting: a rule book with no such application does
    /// one snapshot read and returns.
    pub fn flush(&self, now: SystemTime) -> FlushSummary {
        let mut summary = FlushSummary::default();
        let Some(sid) = (self.active_sid)() else {
            return summary;
        };
        let Some(snapshot) = self.rules.active_rules_for(&sid) else {
            return summary;
        };
        for pattern in routed_app_patterns(&snapshot.rule_book.secondary) {
            // The same slice the codegen enforces: sorted, capped identically,
            // so nothing is persisted that could not become a route anyway.
            let ips = self.observations.ips_for_app(&pattern);
            if ips.is_empty() {
                continue;
            }
            let ips = &ips[..ips.len().min(PER_HOSTNAME_IP_CAP)];
            (self.persist)(&pattern, ips, now);
            summary.apps = summary.apps.saturating_add(1);
            summary.destinations = summary.destinations.saturating_add(ips.len() as u32);
        }
        summary
    }
}

/// The application patterns of `set` whose rules actually produce host routes:
/// enabled, routing (not blocking), and carrying no address condition.
///
/// A rule with both an application and an address matches as AND, and no route
/// table can scope a route to a process, so `generate_secondary_routes` emits
/// nothing for it — remembering its destinations would be dead weight. Deduped
/// and ordered so a flush pass is deterministic.
fn routed_app_patterns(set: &CanonicalRuleSet) -> BTreeSet<String> {
    set.rules()
        .iter()
        .filter(|r| r.enabled && matches!(r.action, RuleAction::Route))
        .filter(|r| r.address_match.is_none())
        .filter_map(|r| r.app_match.as_ref())
        .map(|app| match &app.pattern {
            CanonicalAppPattern::Exact(s) | CanonicalAppPattern::Glob(s) => s.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
    use crate::per_sid_orchestrator::ActiveRulesSnapshot;
    use crate::route_codegen::{generate_secondary_routes, SecondaryRouteTarget};
    use nrr_domain::canonical::{
        CanonicalAddressMatch, CanonicalAppMatch, CanonicalRule, CanonicalRuleBook,
    };
    use nrr_domain::{RouteBehaviorMode, RuleId};
    use std::collections::HashSet;
    use std::sync::Mutex;

    fn ip(d: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, d)
    }

    fn app_rule(id: &str, pattern: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: None,
            app_match: Some(CanonicalAppMatch {
                pattern: CanonicalAppPattern::Exact(pattern.into()),
                include_child_processes: false,
            }),
            comment: String::new(),
            action: RuleAction::Route,
            origin: None,
        }
    }

    struct FixedRules {
        book: CanonicalRuleBook,
    }
    impl RulesProvider for FixedRules {
        fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
            self.active_rules_for("S-A")
        }
        fn active_rules_for(&self, _principal: &str) -> Option<ActiveRulesSnapshot> {
            Some(ActiveRulesSnapshot {
                rule_book: self.book.clone(),
                behavior_mode: RouteBehaviorMode::PreferPrimary,
            })
        }
    }

    fn book(secondary: Vec<CanonicalRule>) -> CanonicalRuleBook {
        CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![]),
            secondary: CanonicalRuleSet::from_rules(secondary),
        }
    }

    /// Persisted rows shared between the fake persist + load closures, so one
    /// fixture exercises a full session hand-off.
    #[derive(Default)]
    struct FakeTable {
        rows: Mutex<Vec<(String, Ipv4Addr, SystemTime)>>,
    }

    impl FakeTable {
        fn persist_fn(table: &Arc<FakeTable>) -> AppDestinationPersistFn {
            let table = Arc::clone(table);
            Arc::new(move |app: &str, ips: &[Ipv4Addr], now: SystemTime| {
                let mut g = table.rows.lock().unwrap_or_else(|p| p.into_inner());
                for ip in ips {
                    g.retain(|(a, i, _)| !(a == app && i == ip));
                    g.push((app.to_string(), *ip, now));
                }
            })
        }

        fn load_fn(table: &Arc<FakeTable>) -> AppDestinationLoadFn {
            let table = Arc::clone(table);
            Arc::new(move |cutoff: SystemTime| {
                let g = table.rows.lock().unwrap_or_else(|p| p.into_inner());
                g.iter()
                    .filter(|(_, _, at)| *at >= cutoff)
                    .map(|(a, i, _)| (a.clone(), *i))
                    .collect()
            })
        }

        fn len(&self) -> usize {
            self.rows.lock().unwrap_or_else(|p| p.into_inner()).len()
        }
    }

    fn memory(
        store: &Arc<AppObservationStore>,
        rules: CanonicalRuleBook,
        table: &Arc<FakeTable>,
    ) -> AppDestinationMemory {
        AppDestinationMemory::new(
            Arc::clone(store),
            Arc::new(FixedRules { book: rules }) as Arc<dyn RulesProvider>,
            Arc::new(|| Some("S-A".to_string())),
            FakeTable::persist_fn(table),
            FakeTable::load_fn(table),
        )
    }

    fn target() -> SecondaryRouteTarget {
        SecondaryRouteTarget {
            gateway: Ipv4Addr::new(10, 8, 0, 1),
            interface_index: 20,
        }
    }

    /// Routes the codegen produces for `rules` against `store` — the real
    /// pipeline, so the assertions are about enforcement, not about the memory
    /// module's own bookkeeping.
    fn routes_for(rules: &CanonicalRuleBook, store: &AppObservationStore) -> Vec<Ipv4Addr> {
        let out = generate_secondary_routes(
            &rules.secondary,
            &target(),
            &MockFqdnCacheLookup::new(),
            store,
            &HashSet::new(),
        );
        out.routes.into_iter().map(|r| r.destination).collect()
    }

    #[test]
    fn a_remembered_destination_routes_before_the_first_observation() {
        // The whole point: session one learned the address the hard way, session
        // two must have its route in place before the app connects at all.
        let table = Arc::new(FakeTable::default());
        let rules = book(vec![app_rule("r1", "telegram.exe")]);

        let first = Arc::new(AppObservationStore::new());
        first.record(r"C:\Users\u\AppData\Telegram\Telegram.exe", ip(7));
        let mem = memory(&first, rules.clone(), &table);
        assert_eq!(
            mem.flush(SystemTime::now()),
            FlushSummary {
                apps: 1,
                destinations: 1
            }
        );

        // A fresh session: nothing observed yet, so today's behaviour is no
        // route at all.
        let second = Arc::new(AppObservationStore::new());
        assert!(routes_for(&rules, &second).is_empty());
        // After the warm load the route exists with zero observations.
        let mem = memory(&second, rules.clone(), &table);
        assert_eq!(mem.warm_load(SystemTime::now()), 1);
        assert_eq!(routes_for(&rules, &second), vec![ip(7)]);
    }

    #[test]
    fn without_a_warm_load_behaviour_is_unchanged() {
        // The pre-seed is additive: a service that never warm-loads (no state
        // DB, or a first-ever start) produces exactly the pre-existing output —
        // no routes and the "not observed yet" diagnostic.
        let rules = book(vec![app_rule("r1", "telegram.exe")]);
        let store = AppObservationStore::new();
        let out = generate_secondary_routes(
            &rules.secondary,
            &target(),
            &MockFqdnCacheLookup::new(),
            &store,
            &HashSet::new(),
        );
        assert!(out.routes.is_empty());
        assert_eq!(
            out.diagnostics,
            vec![
                crate::route_codegen::RouteCodegenDiagnostic::AppRuleUnobserved {
                    rule_id: "r1".to_string(),
                    app: "telegram.exe".to_string(),
                }
            ]
        );
    }

    #[test]
    fn a_remembered_destination_opens_nothing_for_an_app_without_a_rule() {
        // The codegen iterates RULES, so a pre-seeded destination for a process
        // nobody routed produces no route — the memory cannot widen enforcement.
        let table = Arc::new(FakeTable::default());
        let rules = book(vec![app_rule("r1", "telegram.exe")]);
        FakeTable::persist_fn(&table)("chrome.exe", &[ip(9)], SystemTime::now());

        let store = Arc::new(AppObservationStore::new());
        let mem = memory(&store, rules.clone(), &table);
        assert_eq!(mem.warm_load(SystemTime::now()), 1, "the row is loaded…");
        assert!(
            routes_for(&rules, &store).is_empty(),
            "…but no rule names chrome.exe, so nothing is routed"
        );
        assert_eq!(store.ips_for_app("chrome.exe"), vec![ip(9)]);
    }

    #[test]
    fn flush_writes_back_only_route_rule_apps_of_the_additional_link() {
        let table = Arc::new(FakeTable::default());
        let store = Arc::new(AppObservationStore::new());
        for app in ["telegram.exe", "chrome.exe", "blocked.exe", "paired.exe"] {
            store.record(app, ip(5));
        }
        let mut blocked = app_rule("r-block", "blocked.exe");
        blocked.action = RuleAction::Block;
        let mut disabled = app_rule("r-off", "chrome.exe");
        disabled.enabled = false;
        // An app rule that ALSO names an address produces no route (the two
        // match as AND and a route cannot be process-scoped), so its
        // destinations are not worth remembering either.
        let mut paired = app_rule("r-pair", "paired.exe");
        paired.address_match = Some(CanonicalAddressMatch::ExactIp(ip(200)));

        let mut rules = book(vec![
            app_rule("r1", "telegram.exe"),
            blocked,
            disabled,
            paired,
        ]);
        // A primary-bound app rule must not be written back either.
        rules.primary = CanonicalRuleSet::from_rules(vec![app_rule("r-prim", "main.exe")]);
        store.record("main.exe", ip(6));

        let mem = memory(&store, rules, &table);
        assert_eq!(
            mem.flush(SystemTime::now()),
            FlushSummary {
                apps: 1,
                destinations: 1
            }
        );
        assert_eq!(table.len(), 1);
        assert_eq!(
            table.rows.lock().unwrap_or_else(|p| p.into_inner())[0].0,
            "telegram.exe"
        );
    }

    #[test]
    fn a_destination_outside_the_confirmation_window_is_not_re_seeded() {
        let table = Arc::new(FakeTable::default());
        let rules = book(vec![app_rule("r1", "telegram.exe")]);
        let now = SystemTime::now();
        let stale = now
            .checked_sub(ENFORCEMENT_CONFIRMATION_WINDOW + Duration::from_secs(60))
            .expect("clock past the epoch");
        FakeTable::persist_fn(&table)("telegram.exe", &[ip(1)], stale);
        FakeTable::persist_fn(&table)("telegram.exe", &[ip(2)], now);

        let store = Arc::new(AppObservationStore::new());
        let mem = memory(&store, rules.clone(), &table);
        assert_eq!(mem.warm_load(now), 1);
        assert_eq!(
            routes_for(&rules, &store),
            vec![ip(2)],
            "only the address still in use enforces"
        );
    }

    #[test]
    fn a_flush_restamps_addresses_still_in_use() {
        // A long-running app keeps a fixed destination set; without the restamp
        // it would age out of the window mid-session and stop being seeded.
        let table = Arc::new(FakeTable::default());
        let rules = book(vec![app_rule("r1", "telegram.exe")]);
        let store = Arc::new(AppObservationStore::new());
        store.record("telegram.exe", ip(1));
        let mem = memory(&store, rules.clone(), &table);

        let long_ago = SystemTime::now()
            .checked_sub(ENFORCEMENT_CONFIRMATION_WINDOW + Duration::from_secs(60))
            .expect("clock past the epoch");
        mem.flush(long_ago);
        let now = SystemTime::now();
        assert_eq!(mem.warm_load(now), 0, "the stale stamp is withheld");
        mem.flush(now);

        let next_session = Arc::new(AppObservationStore::new());
        let mem = memory(&next_session, rules.clone(), &table);
        assert_eq!(mem.warm_load(now), 1);
        assert_eq!(routes_for(&rules, &next_session), vec![ip(1)]);
    }

    #[test]
    fn flush_without_an_active_sid_or_app_rules_does_nothing() {
        let table = Arc::new(FakeTable::default());
        let store = Arc::new(AppObservationStore::new());
        store.record("telegram.exe", ip(1));

        // No routed app rule at all — one snapshot read, no writes.
        let mem = memory(&store, book(vec![]), &table);
        assert_eq!(mem.flush(SystemTime::now()), FlushSummary::default());

        // No routing-active user — not even the snapshot read.
        let mem = AppDestinationMemory::new(
            Arc::clone(&store),
            Arc::new(FixedRules {
                book: book(vec![app_rule("r1", "telegram.exe")]),
            }) as Arc<dyn RulesProvider>,
            Arc::new(|| None),
            FakeTable::persist_fn(&table),
            FakeTable::load_fn(&table),
        );
        assert_eq!(mem.flush(SystemTime::now()), FlushSummary::default());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn glob_app_patterns_round_trip_through_their_own_key() {
        // A glob rule is persisted under the pattern the codegen queries with,
        // so the reload reproduces exactly the set the previous session enforced
        // — without re-deriving which processes the glob covered.
        let table = Arc::new(FakeTable::default());
        let mut rule = app_rule("r1", "*vpn*.exe");
        rule.app_match = Some(CanonicalAppMatch {
            pattern: CanonicalAppPattern::Glob("*vpn*.exe".into()),
            include_child_processes: false,
        });
        let rules = book(vec![rule]);

        let first = Arc::new(AppObservationStore::new());
        first.record("myvpnclient.exe", ip(3));
        let mem = memory(&first, rules.clone(), &table);
        assert_eq!(mem.flush(SystemTime::now()).destinations, 1);

        let second = Arc::new(AppObservationStore::new());
        let mem = memory(&second, rules.clone(), &table);
        assert_eq!(mem.warm_load(SystemTime::now()), 1);
        assert_eq!(routes_for(&rules, &second), vec![ip(3)]);
    }
}
