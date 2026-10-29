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
//! address, after which the route follows within a tick.
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
//! Addresses a rule names — exactly, or inside a subnet or range — are the
//! opposite case: they are policy, not observation, and belong to that rule, so
//! they are never written back as an application's destinations.
//!
//! ## Whose destinations
//!
//! Where observations are kept per user, each row is written with its user and
//! seeds only that user's store: an address Alice's browser used must never
//! become a route in Bob's plan. A machine-wide store writes and reads rows
//! with no owner. A row without an owner therefore never reaches a per-user
//! store — including every row written before rows had owners — and ages out.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use nrr_domain::canonical::{CanonicalAppPattern, CanonicalRuleBook, CanonicalRuleSet};
use nrr_domain::decision_matching::{MatchClass, RequestedRouteDecision, ZonePriorityPolicy};
use nrr_domain::{RouteBehaviorMode, RuleAction};

use crate::app_observation_lookup::{AppObservationLookup, AppObservationStore};
use crate::fqdn_cache_lookup::ENFORCEMENT_CONFIRMATION_WINDOW;
use crate::per_sid_orchestrator::RulesProvider;
use crate::wfp_codegen::PER_HOSTNAME_IP_CAP;

pub use nrr_storage::app_destinations::RememberedDestination;

/// Persist one application's currently-known destinations for an owner (`None`
/// for a machine-wide store), stamped with the confirmation time. The
/// production impl writes
/// `nrr_storage::app_destinations::AppDestinationsRepository::upsert`.
pub type AppDestinationPersistFn =
    Arc<dyn Fn(Option<&str>, &str, &[IpAddr], SystemTime) + Send + Sync>;

/// Load every remembered destination confirmed at or after the given instant,
/// with its owner, newest first. The production impl reads
/// `nrr_storage::app_destinations::AppDestinationsRepository::load_confirmed_since`
/// and prunes what falls outside it.
pub type AppDestinationLoadFn = Arc<dyn Fn(SystemTime) -> Vec<RememberedDestination> + Send + Sync>;

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
    /// Everyone whose rules are in force. A list, not one user: on a machine
    /// with several logged in, persisting only the first one's destinations
    /// means the others' application rules start every session cold.
    present: crate::service_tasks::PresentPrincipalsFn,
    persist: AppDestinationPersistFn,
    load: AppDestinationLoadFn,
    /// How recently a destination must have been confirmed to be re-seeded.
    /// See the module docs — this is the shared enforcement window, overridable
    /// only so tests can exercise the boundary without sleeping.
    window: Duration,
    /// A principal's `app_rules_take_all_addresses`. With it on, an address
    /// another rule names is the program's too, and remembered like the rest.
    app_takeover: AppTakeoverFn,
}

/// Whether a principal's application rules take all their addresses.
pub type AppTakeoverFn = Arc<dyn Fn(&str) -> bool + Send + Sync>;

impl AppDestinationMemory {
    pub fn new(
        observations: Arc<AppObservationStore>,
        rules: Arc<dyn RulesProvider>,
        present: crate::service_tasks::PresentPrincipalsFn,
        persist: AppDestinationPersistFn,
        load: AppDestinationLoadFn,
    ) -> Self {
        Self {
            observations,
            rules,
            present,
            persist,
            load,
            window: ENFORCEMENT_CONFIRMATION_WINDOW,
            app_takeover: Arc::new(|_| false),
        }
    }

    /// Read each principal's takeover setting (off for everyone by default).
    pub fn with_app_takeover(mut self, app_takeover: AppTakeoverFn) -> Self {
        self.app_takeover = app_takeover;
        self
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
        let mut rows = (self.load)(cutoff);
        if rows.is_empty() {
            return 0;
        }
        // Rows come newest first; seeded oldest first, the newest is the last
        // to give way, as it was before the restart.
        rows.reverse();
        let seeded = if self.observations.keeps_per_principal() {
            self.seed_each_owner(rows)
        } else {
            self.seed_machine_wide(rows)
        };
        if seeded > 0 {
            tracing::info!(
                target: "nrr::app-routing",
                msg_key = "appdestmem-preseeded",
                destinations = seeded,
                "pre-seeded application destinations from earlier sessions — their routes exist before the first connection",
            );
        }
        seeded
    }

    /// The machine-wide store takes the rows with no owner. Rows an earlier
    /// build wrote passed an older filter: hold them to the one `flush` applies
    /// today. With nobody's rules readable yet there is nothing to hold them
    /// to; codegen still gates them by the rules.
    fn seed_machine_wide(&self, rows: Vec<RememberedDestination>) -> usize {
        let pairs: Vec<(String, IpAddr)> = rows
            .into_iter()
            .filter(|row| row.owner.is_none())
            .map(|row| (row.app_key, row.ip))
            .collect();
        let books = self.present_books();
        let pairs: Vec<(String, IpAddr)> = if books.is_empty() {
            pairs
        } else {
            pairs
                .into_iter()
                .filter(|(key, ip)| {
                    books
                        .iter()
                        .any(|(book, gate)| admits(book, gate, key, *ip))
                })
                .collect()
        };
        self.observations.seed_many(&pairs)
    }

    /// Kept per user, each owner's rows go into that owner's store alone, held
    /// to that owner's rules where they are readable. A row with no owner
    /// seeds nobody.
    fn seed_each_owner(&self, rows: Vec<RememberedDestination>) -> usize {
        let mut by_owner: BTreeMap<String, Vec<(String, IpAddr)>> = BTreeMap::new();
        for row in rows {
            if let Some(owner) = row.owner {
                by_owner
                    .entry(owner)
                    .or_default()
                    .push((row.app_key, row.ip));
            }
        }
        let mut seeded = 0;
        for (owner, pairs) in by_owner {
            let Some(store) = self.observations.scope_for(Some(&owner)) else {
                continue;
            };
            let pairs: Vec<(String, IpAddr)> = match self.rules.active_rules_for(&owner) {
                Some(snapshot) => {
                    let gate = self.gate(&owner, &snapshot.rule_book);
                    pairs
                        .into_iter()
                        .filter(|(key, ip)| admits(&snapshot.rule_book, &gate, key, *ip))
                        .collect()
                }
                None => pairs,
            };
            seeded += store.seed_many(&pairs);
        }
        seeded
    }

    /// Write back the destinations of every application the active user's rule
    /// book routes over the additional link, restamping each one's confirmation
    /// time. Cheap and self-limiting: a rule book with no such application does
    /// one snapshot read and returns.
    pub fn flush(&self, now: SystemTime) -> FlushSummary {
        // Before anything is written back: a pair a tunnel now carries must not
        // be re-confirmed, and its stored row then ages out on its own.
        self.observations.shed_foreign();
        let mut summary = FlushSummary::default();
        let mut written: std::collections::HashSet<String> = std::collections::HashSet::new();
        for sid in (self.present)() {
            let Some(snapshot) = self.rules.active_rules_for(&sid) else {
                continue;
            };
            self.flush_for(&sid, &snapshot, now, &mut written, &mut summary);
        }
        summary
    }

    /// The rule books in force with what each lets a program keep: every
    /// present user's, else the active one under the default.
    fn present_books(&self) -> Vec<(CanonicalRuleBook, ProgramAddresses)> {
        let mut books: Vec<(CanonicalRuleBook, ProgramAddresses)> = (self.present)()
            .iter()
            .filter_map(|sid| {
                let book = self.rules.active_rules_for(sid)?.rule_book;
                let gate = self.gate(sid, &book);
                Some((book, gate))
            })
            .collect();
        if books.is_empty() {
            books.extend(
                self.rules
                    .active_rules()
                    .map(|snapshot| (snapshot.rule_book, ProgramAddresses::Unnamed)),
            );
        }
        books
    }

    /// What `sid`'s settings let a program of `book` keep.
    fn gate(&self, sid: &str, book: &CanonicalRuleBook) -> ProgramAddresses {
        if (self.app_takeover)(sid) {
            ProgramAddresses::AllBut(crate::address_ownership::app_takeover_vetoes(
                book,
                crate::wfp_codegen::current_rule_shape_support(),
            ))
        } else {
            ProgramAddresses::Unnamed
        }
    }

    /// Write back one principal's routed applications. `written` spans the whole
    /// pass: two users routing the same application share its destinations, and
    /// persisting them twice would double the reported counts.
    fn flush_for(
        &self,
        sid: &str,
        snapshot: &crate::per_sid_orchestrator::ActiveRulesSnapshot,
        now: SystemTime,
        written: &mut std::collections::HashSet<String>,
        summary: &mut FlushSummary,
    ) {
        // Kept per user, the destinations are this user's own.
        let Some(observations) = self.observations.scope_for(Some(sid)) else {
            return;
        };
        let owner = self.observations.keeps_per_principal().then_some(sid);
        let gate = self.gate(sid, &snapshot.rule_book);
        for pattern in routed_app_patterns(&snapshot.rule_book.secondary) {
            // The column is `app_key` and the observation store answers on
            // keys; persisting the rule spelling instead left rows nothing
            // could later withdraw.
            let key = crate::app_observation_lookup::observation_key(&pattern);
            // Shared observations are written once; a user's own, once each.
            let written_as = match owner {
                Some(owner) => format!("{owner}/{key}"),
                None => key.clone(),
            };
            if key.is_empty() || !written.insert(written_as) {
                continue;
            }
            // The slice the filters carry: the most recently used, capped
            // identically per family, so a restart brings back the current
            // servers of both.
            let v4 = observations.ips_for_app(&pattern);
            let v6 = observations.ips_v6_for_app(&pattern);
            if v4.is_empty() && v6.is_empty() {
                continue;
            }
            let ips: Vec<IpAddr> = observations
                .latest_among(&pattern, &v4, PER_HOSTNAME_IP_CAP)
                .into_iter()
                .map(IpAddr::V4)
                .chain(
                    observations
                        .latest_among(&pattern, &v6, PER_HOSTNAME_IP_CAP)
                        .into_iter()
                        .map(IpAddr::V6),
                )
                .collect();
            // Only what was actually seen since the last pass. The store also
            // holds addresses re-seeded from earlier sessions and ones last
            // used hours ago; writing those with `now` re-confirms them on
            // every flush, so the freshness window never expires and
            // `prune_before` never has anything to prune. Untouched rows keep
            // the `learned_at` they earned — the upsert only moves it forward
            // for the addresses named here.
            let seen = observations.take_seen_since_flush(&pattern);
            let confirmed: Vec<IpAddr> = ips
                .iter()
                .copied()
                .filter(|ip| seen.contains(ip))
                .filter(|ip| gate.keeps(&snapshot.rule_book, *ip))
                .collect();
            if confirmed.is_empty() {
                continue;
            }
            (self.persist)(owner, &key, &confirmed, now);
            summary.apps = summary.apps.saturating_add(1);
            summary.destinations = summary.destinations.saturating_add(confirmed.len() as u32);
        }
    }
}

/// Which of a program's addresses one principal's rules leave to it.
enum ProgramAddresses {
    /// An address an address rule names is that rule's.
    Unnamed,
    /// Application rules take all their addresses, but those listed.
    AllBut(std::collections::HashSet<std::net::IpAddr>),
}

impl ProgramAddresses {
    fn keeps(&self, book: &CanonicalRuleBook, ip: IpAddr) -> bool {
        match self {
            Self::Unnamed => !named_by_address_rule(book, ip),
            Self::AllBut(vetoes) => !vetoes.contains(&ip),
        }
    }
}

/// Whether `book` would let `flush` write `ip` for the application keyed `key`.
/// Keys are compared normalised: earlier builds stored the rule spelling.
fn admits(book: &CanonicalRuleBook, gate: &ProgramAddresses, key: &str, ip: IpAddr) -> bool {
    let key = crate::app_observation_lookup::observation_key(key);
    routed_app_patterns(&book.secondary)
        .iter()
        .any(|pattern| crate::app_observation_lookup::observation_key(pattern) == key)
        && gate.keeps(book, ip)
}

/// Whether an address rule — an exact address, or a subnet or range holding it
/// — names `ip` for every process. Asked of the engine, so "names" means what
/// the matcher says, not a second reading of the rule kinds.
fn named_by_address_rule(book: &CanonicalRuleBook, ip: IpAddr) -> bool {
    matches!(
        nrr_domain::decision_engine_input::match_sample(
            book,
            None,
            Some(ip),
            None,
            ZonePriorityPolicy::default(),
            RouteBehaviorMode::PreferPrimary,
        ),
        RequestedRouteDecision::MatchedRoute { candidate }
            if matches!(candidate.match_class, MatchClass::ExactIp | MatchClass::Subnet)
    )
}

/// The application patterns of `set` whose rules actually produce host routes:
/// enabled, routing (not blocking), and carrying no address condition.
///
/// A rule with both an application and an address matches as AND, and no route
/// table can scope a route to a process, so `generate_secondary_routes` emits
/// nothing for it — remembering its destinations would be dead weight. Deduped
/// and ordered so a flush pass is deterministic.
pub fn routed_app_patterns(set: &CanonicalRuleSet) -> BTreeSet<String> {
    set.rules()
        .iter()
        .filter(|r| r.enabled && matches!(r.action, RuleAction::Route))
        .filter(|r| r.address_match.is_none())
        .filter_map(|r| r.app_match.as_ref())
        .map(|app| match &app.pattern {
            CanonicalAppPattern::Exact(s) | CanonicalAppPattern::Glob(s) => s.clone(),
            // Its observations are kept under its canonical spelling.
            CanonicalAppPattern::Path(path) => path.as_str().to_string(),
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
    use nrr_domain::RuleId;
    use std::collections::HashSet;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Mutex;

    fn ip(d: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, d)
    }

    fn at(d: u8) -> IpAddr {
        IpAddr::V4(ip(d))
    }

    fn app_rule(id: &str, pattern: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: None,
            app_match: Some(CanonicalAppMatch {
                pattern: CanonicalAppPattern::Exact(pattern.into()),
                include_child_processes: false,
                override_requested: false,
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
    type PersistedRow = (Option<String>, String, IpAddr, SystemTime);

    #[derive(Default)]
    struct FakeTable {
        rows: Mutex<Vec<PersistedRow>>,
    }

    impl FakeTable {
        fn persist_fn(table: &Arc<FakeTable>) -> AppDestinationPersistFn {
            let table = Arc::clone(table);
            Arc::new(
                move |owner: Option<&str>, app: &str, ips: &[IpAddr], now: SystemTime| {
                    let mut g = table.rows.lock().unwrap_or_else(|p| p.into_inner());
                    for ip in ips {
                        g.retain(|(o, a, i, _)| !(o.as_deref() == owner && a == app && i == ip));
                        g.push((owner.map(str::to_owned), app.to_string(), *ip, now));
                    }
                },
            )
        }

        fn load_fn(table: &Arc<FakeTable>) -> AppDestinationLoadFn {
            let table = Arc::clone(table);
            Arc::new(move |cutoff: SystemTime| {
                let g = table.rows.lock().unwrap_or_else(|p| p.into_inner());
                // Newest first, as the production query answers.
                let mut rows: Vec<_> = g.iter().collect();
                rows.sort_by(|a, b| b.3.cmp(&a.3));
                rows.into_iter()
                    .filter(|(_, _, _, at)| *at >= cutoff)
                    .map(|(o, a, i, _)| RememberedDestination {
                        owner: o.clone(),
                        app_key: a.clone(),
                        ip: *i,
                    })
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
            Arc::new(|| vec!["S-A".to_string()]),
            FakeTable::persist_fn(table),
            FakeTable::load_fn(table),
        )
    }

    fn target() -> SecondaryRouteTarget {
        SecondaryRouteTarget {
            gateway: Ipv4Addr::new(10, 8, 0, 1),
            gateway_v6: None,
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
            &crate::address_ownership::AddressOwnership::default(),
            crate::address_ownership::Link::Additional,
        );
        out.routes
            .into_iter()
            .filter_map(|r| match r.destination {
                IpAddr::V4(d) => Some(d),
                IpAddr::V6(_) => None,
            })
            .collect()
    }

    #[test]
    fn a_remembered_destination_routes_before_the_first_observation() {
        // The whole point: session one learned the address the hard way, session
        // two must have its route in place before the app connects at all.
        let table = Arc::new(FakeTable::default());
        let rules = book(vec![app_rule("r1", "messenger.exe")]);

        let first = Arc::new(AppObservationStore::new());
        first.record(r"C:\Users\u\AppData\Messenger\Messenger.exe", ip(7));
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
        let rules = book(vec![app_rule("r1", "messenger.exe")]);
        let store = AppObservationStore::new();
        let out = generate_secondary_routes(
            &rules.secondary,
            &target(),
            &MockFqdnCacheLookup::new(),
            &store,
            &HashSet::new(),
            &crate::address_ownership::AddressOwnership::default(),
            crate::address_ownership::Link::Additional,
        );
        assert!(out.routes.is_empty());
        assert_eq!(
            out.diagnostics,
            vec![
                crate::route_codegen::RouteCodegenDiagnostic::AppRuleUnobserved {
                    rule_id: "r1".to_string(),
                    app: "messenger.exe".to_string(),
                }
            ]
        );
    }

    #[test]
    fn a_remembered_destination_opens_nothing_for_an_app_without_a_rule() {
        // Held to today's flush filter: no rule routes chrome.exe, so its row
        // from an earlier session is not loaded at all.
        let table = Arc::new(FakeTable::default());
        let rules = book(vec![app_rule("r1", "messenger.exe")]);
        FakeTable::persist_fn(&table)(None, "chrome.exe", &[at(9)], SystemTime::now());

        let store = Arc::new(AppObservationStore::new());
        let mem = memory(&store, rules.clone(), &table);
        assert_eq!(mem.warm_load(SystemTime::now()), 0);
        assert!(routes_for(&rules, &store).is_empty());
        assert!(store.ips_for_app("chrome.exe").is_empty());
    }

    /// Rows an earlier build wrote for an address a rule now names — routed or
    /// blocked — stay in the table but never reach the store.
    #[test]
    fn a_remembered_address_a_rule_now_names_is_not_loaded() {
        let table = Arc::new(FakeTable::default());
        let now = SystemTime::now();
        FakeTable::persist_fn(&table)(None, "messenger", &[at(5), at(50), at(60)], now);
        let mut rules = book(vec![app_rule("r1", "messenger.exe")]);
        let address = |id: &str, ip: Ipv4Addr| CanonicalRule {
            address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(ip))),
            app_match: None,
            ..app_rule(id, "unused.exe")
        };
        let mut blocked = address("b-1", ip(60));
        blocked.action = RuleAction::Block;
        rules.primary = CanonicalRuleSet::from_rules(vec![address("i-1", ip(50)), blocked]);

        let store = Arc::new(AppObservationStore::new());
        let mem = memory(&store, rules, &table);
        assert_eq!(mem.warm_load(now), 1);
        assert_eq!(store.ips_for_app("messenger.exe"), vec![ip(5)]);
    }

    /// An address only a Block rule names is not an app destination either.
    #[test]
    fn an_address_only_a_block_rule_names_is_not_remembered() {
        let table = Arc::new(FakeTable::default());
        let store = Arc::new(AppObservationStore::new());
        store.record("messenger.exe", ip(5));
        store.record("messenger.exe", ip(60));
        let mut rules = book(vec![app_rule("r1", "messenger.exe")]);
        rules.primary = CanonicalRuleSet::from_rules(vec![CanonicalRule {
            address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(ip(60)))),
            app_match: None,
            action: RuleAction::Block,
            ..app_rule("b-1", "unused.exe")
        }]);

        let mem = memory(&store, rules, &table);
        mem.flush(SystemTime::now());
        let rows = table.rows.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(rows.iter().map(|r| r.2).collect::<Vec<_>>(), vec![ip(5)]);
    }

    /// Each signed-in user's own book, by SID.
    struct TwoUsersRules;
    impl RulesProvider for TwoUsersRules {
        fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
            None
        }
        fn active_rules_for(&self, principal: &str) -> Option<ActiveRulesSnapshot> {
            let app = match principal {
                "S-A" => "messenger.exe",
                "S-B" => "chat.exe",
                _ => return None,
            };
            Some(ActiveRulesSnapshot {
                rule_book: book(vec![app_rule(principal, app)]),
            })
        }
    }

    #[test]
    fn every_signed_in_users_application_destinations_are_remembered() {
        // A fresh store each time: a flush drains what it has written back.
        let flushed = |present: Vec<&'static str>| {
            let store = Arc::new(AppObservationStore::new());
            store.record("messenger.exe", ip(7));
            store.record("chat.exe", ip(8));
            let table = Arc::new(FakeTable::default());
            let mem = AppDestinationMemory::new(
                Arc::clone(&store),
                Arc::new(TwoUsersRules) as Arc<dyn RulesProvider>,
                Arc::new(move || present.iter().map(|s| (*s).to_owned()).collect()),
                FakeTable::persist_fn(&table),
                FakeTable::load_fn(&table),
            );
            mem.flush(SystemTime::now()).apps
        };
        // Handed the console user alone, the second user's rule starts cold.
        assert_eq!(flushed(vec!["S-A"]), 1);
        assert_eq!(flushed(vec!["S-A", "S-B"]), 2);
    }

    #[test]
    fn flush_writes_back_only_route_rule_apps_of_the_additional_link() {
        let table = Arc::new(FakeTable::default());
        let store = Arc::new(AppObservationStore::new());
        for app in ["messenger.exe", "chrome.exe", "blocked.exe", "paired.exe"] {
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
        paired.address_match = Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(ip(200))));

        let mut rules = book(vec![
            app_rule("r1", "messenger.exe"),
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
        // Persisted under the observation key, which is what a later
        // withdrawal looks the row up by.
        assert_eq!(
            table.rows.lock().unwrap_or_else(|p| p.into_inner())[0].1,
            "messenger"
        );
    }

    #[test]
    fn an_address_a_network_or_exact_rule_names_is_not_remembered_for_an_app() {
        let table = Arc::new(FakeTable::default());
        let store = Arc::new(AppObservationStore::new());
        let in_network = Ipv4Addr::new(198, 51, 100, 9);
        let exact = ip(50);
        for seen in [ip(5), in_network, exact] {
            store.record("messenger.exe", seen);
        }
        let mut rules = book(vec![app_rule("r1", "messenger.exe")]);
        let address = |id: &str, m: CanonicalAddressMatch| CanonicalRule {
            address_match: Some(m),
            app_match: None,
            ..app_rule(id, "unused.exe")
        };
        rules.primary = CanonicalRuleSet::from_rules(vec![
            address(
                "n-1",
                CanonicalAddressMatch::Subnet(
                    nrr_shared::ip_block::IpBlock::parse("198.51.100.0/24").expect("network"),
                ),
            ),
            address("i-1", CanonicalAddressMatch::ExactIp(IpAddr::V4(exact))),
        ]);

        let mem = memory(&store, rules, &table);
        assert_eq!(
            mem.flush(SystemTime::now()),
            FlushSummary {
                apps: 1,
                destinations: 1
            }
        );
        let rows = table.rows.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(rows.iter().map(|r| r.2).collect::<Vec<_>>(), vec![ip(5)]);
    }

    /// Primary rules naming 50 exactly and 198.51.100.0/24 as a network, and a
    /// literal-IP Block on 60.
    fn named_and_blocked(rules: &mut CanonicalRuleBook) {
        let address = |id: &str, m: CanonicalAddressMatch| CanonicalRule {
            address_match: Some(m),
            app_match: None,
            ..app_rule(id, "unused.exe")
        };
        let mut blocked = address("b-1", CanonicalAddressMatch::ExactIp(IpAddr::V4(ip(60))));
        blocked.action = RuleAction::Block;
        rules.primary = CanonicalRuleSet::from_rules(vec![
            address(
                "n-1",
                CanonicalAddressMatch::Subnet(
                    nrr_shared::ip_block::IpBlock::parse("198.51.100.0/24").expect("network"),
                ),
            ),
            address("i-1", CanonicalAddressMatch::ExactIp(IpAddr::V4(ip(50)))),
            blocked,
        ]);
    }

    /// With the takeover setting the program takes the addresses other rules
    /// name, so they are its destinations and must start warm after a
    /// restart; a literal-IP Block's address is never the program's.
    #[test]
    fn under_the_takeover_setting_a_named_address_is_remembered_for_the_app() {
        let table = Arc::new(FakeTable::default());
        let store = Arc::new(AppObservationStore::new());
        let in_network = Ipv4Addr::new(198, 51, 100, 9);
        for seen in [ip(5), in_network, ip(50), ip(60)] {
            store.record("messenger.exe", seen);
        }
        let mut rules = book(vec![app_rule("r1", "messenger.exe")]);
        named_and_blocked(&mut rules);

        let mem = memory(&store, rules, &table).with_app_takeover(Arc::new(|sid| sid == "S-A"));
        mem.flush(SystemTime::now());
        let mut rows: Vec<IpAddr> = table
            .rows
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|r| r.2)
            .collect();
        rows.sort();
        assert_eq!(rows, vec![IpAddr::V4(in_network), at(5), at(50)]);
    }

    /// The same rows, read back at start-up under the setting.
    #[test]
    fn under_the_takeover_setting_a_remembered_named_address_is_loaded() {
        let table = Arc::new(FakeTable::default());
        let now = SystemTime::now();
        FakeTable::persist_fn(&table)(None, "messenger", &[at(5), at(50), at(60)], now);
        let mut rules = book(vec![app_rule("r1", "messenger.exe")]);
        named_and_blocked(&mut rules);

        let store = Arc::new(AppObservationStore::new());
        let mem = memory(&store, rules, &table).with_app_takeover(Arc::new(|_| true));
        assert_eq!(mem.warm_load(now), 2);
        let mut loaded = store.ips_for_app("messenger.exe");
        loaded.sort();
        assert_eq!(loaded, vec![ip(5), ip(50)]);
    }

    /// A program's IPv6 server is remembered like its IPv4 one: forgotten at
    /// a restart, its first v6 connection of every session is held again.
    #[test]
    fn an_ipv6_destination_is_remembered_across_a_restart() {
        let table = Arc::new(FakeTable::default());
        let rules = book(vec![app_rule("r1", "messenger.exe")]);
        let v6: Ipv6Addr = "2001:db8::7".parse().expect("v6");
        let first = Arc::new(AppObservationStore::new());
        first.record("messenger.exe", ip(7));
        first.record("messenger.exe", v6);
        assert_eq!(
            memory(&first, rules.clone(), &table).flush(SystemTime::now()),
            FlushSummary {
                apps: 1,
                destinations: 2
            }
        );

        let second = Arc::new(AppObservationStore::new());
        assert_eq!(
            memory(&second, rules, &table).warm_load(SystemTime::now()),
            2
        );
        assert_eq!(second.ips_v6_for_app("messenger.exe"), vec![v6]);
        assert_eq!(second.ips_for_app("messenger.exe"), vec![ip(7)]);
    }

    /// A messenger that moved to new servers kept its lowest-numbered old ones
    /// across a restart, and paid a held first connection for every current one.
    #[test]
    fn a_busy_program_restarts_with_its_latest_addresses_not_its_lowest() {
        let table = Arc::new(FakeTable::default());
        let rules = book(vec![app_rule("r1", "messenger.exe")]);
        let store = Arc::new(AppObservationStore::new());
        for d in 101..=200 {
            store.record("messenger.exe", ip(d));
        }
        let now = SystemTime::now();
        memory(&store, rules.clone(), &table).flush(now);

        let restarted = Arc::new(AppObservationStore::new());
        assert_eq!(memory(&restarted, rules, &table).warm_load(now), 64);
        let kept = restarted.ips_for_app("messenger.exe");
        assert_eq!(kept, (137..=200).map(ip).collect::<Vec<_>>());
        assert_eq!(restarted.latest_of("messenger.exe", &kept, 64), kept);
    }

    /// The order a program used its addresses survives the restart: the one
    /// used last before it is the last to give way after it.
    #[test]
    fn after_a_restart_the_newest_remembered_address_is_the_last_to_give_way() {
        let table = Arc::new(FakeTable::default());
        let rules = book(vec![app_rule("r1", "messenger.exe")]);
        let now = SystemTime::now();
        let earlier = now
            .checked_sub(Duration::from_secs(60))
            .expect("clock past the epoch");
        FakeTable::persist_fn(&table)(None, "messenger.exe", &[at(1)], earlier);
        FakeTable::persist_fn(&table)(None, "messenger.exe", &[at(2)], now);

        let store = Arc::new(AppObservationStore::with_cap(2));
        assert_eq!(memory(&store, rules, &table).warm_load(now), 2);
        store.record("messenger.exe", ip(3));
        assert_eq!(store.ips_for_app("messenger.exe"), vec![ip(2), ip(3)]);
    }

    #[test]
    fn a_destination_outside_the_confirmation_window_is_not_re_seeded() {
        let table = Arc::new(FakeTable::default());
        let rules = book(vec![app_rule("r1", "messenger.exe")]);
        let now = SystemTime::now();
        let stale = now
            .checked_sub(ENFORCEMENT_CONFIRMATION_WINDOW + Duration::from_secs(60))
            .expect("clock past the epoch");
        FakeTable::persist_fn(&table)(None, "messenger.exe", &[at(1)], stale);
        FakeTable::persist_fn(&table)(None, "messenger.exe", &[at(2)], now);

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
        // "Still in use" means observed again, not merely still in memory: a
        // long-running app keeps touching its destinations, and each sighting
        // is what carries the address forward through the freshness window.
        let table = Arc::new(FakeTable::default());
        let rules = book(vec![app_rule("r1", "messenger.exe")]);
        let store = Arc::new(AppObservationStore::new());
        store.record("messenger.exe", ip(1));
        let mem = memory(&store, rules.clone(), &table);

        let long_ago = SystemTime::now()
            .checked_sub(ENFORCEMENT_CONFIRMATION_WINDOW + Duration::from_secs(60))
            .expect("clock past the epoch");
        mem.flush(long_ago);
        let now = SystemTime::now();
        assert_eq!(mem.warm_load(now), 0, "the stale stamp is withheld");
        store.record("messenger.exe", ip(1));
        mem.flush(now);

        let next_session = Arc::new(AppObservationStore::new());
        let mem = memory(&next_session, rules.clone(), &table);
        assert_eq!(mem.warm_load(now), 1);
        assert_eq!(routes_for(&rules, &next_session), vec![ip(1)]);
    }

    #[test]
    fn a_flush_does_not_re_confirm_an_address_nobody_touched() {
        // The store keeps addresses re-seeded from earlier sessions and ones
        // last used hours ago. Stamping those with `now` on every pass kept the
        // confirmation window from ever expiring, so nothing was ever pruned.
        let table = Arc::new(FakeTable::default());
        let rules = book(vec![app_rule("r1", "messenger.exe")]);
        let store = Arc::new(AppObservationStore::new());
        store.record("messenger.exe", ip(1));
        let mem = memory(&store, rules.clone(), &table);

        let long_ago = SystemTime::now()
            .checked_sub(ENFORCEMENT_CONFIRMATION_WINDOW + Duration::from_secs(60))
            .expect("clock past the epoch");
        mem.flush(long_ago);
        // Nothing observed since: the address is still in memory, but nobody
        // used it.
        let now = SystemTime::now();
        assert_eq!(
            mem.flush(now),
            FlushSummary::default(),
            "an untouched address must not be written again"
        );

        let next_session = Arc::new(AppObservationStore::new());
        let mem = memory(&next_session, rules, &table);
        assert_eq!(
            mem.warm_load(now),
            0,
            "and so it ages out of the window as it should"
        );
    }

    #[test]
    fn flush_without_an_active_sid_or_app_rules_does_nothing() {
        let table = Arc::new(FakeTable::default());
        let store = Arc::new(AppObservationStore::new());
        store.record("messenger.exe", ip(1));

        // No routed app rule at all — one snapshot read, no writes.
        let mem = memory(&store, book(vec![]), &table);
        assert_eq!(mem.flush(SystemTime::now()), FlushSummary::default());

        // No routing-active user — not even the snapshot read.
        let mem = AppDestinationMemory::new(
            Arc::clone(&store),
            Arc::new(FixedRules {
                book: book(vec![app_rule("r1", "messenger.exe")]),
            }) as Arc<dyn RulesProvider>,
            Arc::new(Vec::new),
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
            override_requested: false,
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

    fn plan_of(store: &Arc<AppObservationStore>, principal: &str, app: &str) -> Vec<Ipv4Addr> {
        store
            .scope_for(Some(principal))
            .expect("kept per user")
            .ips_for_app(app)
    }

    /// Kept per user, a remembered destination goes back to its owner alone:
    /// Bob's rule for the same program never routes Alice's addresses, and a
    /// row nobody owns (every row from before rows had owners) seeds nobody.
    #[test]
    fn seeding_gives_each_user_only_their_own_destinations() {
        let table = Arc::new(FakeTable::default());
        let now = SystemTime::now();
        let persist = FakeTable::persist_fn(&table);
        persist(Some("uid:1000"), "firefox", &[at(1)], now);
        persist(Some("uid:1001"), "firefox", &[at(2)], now);
        persist(None, "firefox", &[at(3)], now);

        let store = Arc::new(AppObservationStore::per_principal());
        let mem = memory(&store, book(vec![app_rule("r1", "firefox")]), &table);
        assert_eq!(mem.warm_load(now), 2);
        assert_eq!(plan_of(&store, "uid:1000", "firefox"), vec![ip(1)]);
        assert_eq!(plan_of(&store, "uid:1001", "firefox"), vec![ip(2)]);
        assert!(
            plan_of(&store, "uid:1002", "firefox").is_empty(),
            "a row without an owner reaches nobody"
        );
    }

    /// Kept per user, a flush writes each user's destinations under that user,
    /// and the next session hands them back to that user only.
    #[test]
    fn a_per_user_flush_round_trips_to_the_same_user() {
        let table = Arc::new(FakeTable::default());
        let rules = book(vec![app_rule("r1", "firefox")]);
        let store = Arc::new(AppObservationStore::per_principal());
        store
            .scope_for(Some("uid:1000"))
            .expect("owner known")
            .record("/usr/bin/firefox", ip(7));
        let mem = AppDestinationMemory::new(
            Arc::clone(&store),
            Arc::new(FixedRules {
                book: rules.clone(),
            }) as Arc<dyn RulesProvider>,
            Arc::new(|| vec!["uid:1000".to_string(), "uid:1001".to_string()]),
            FakeTable::persist_fn(&table),
            FakeTable::load_fn(&table),
        );
        assert_eq!(
            mem.flush(SystemTime::now()),
            FlushSummary {
                apps: 1,
                destinations: 1
            }
        );
        {
            let rows = table.rows.lock().unwrap_or_else(|p| p.into_inner());
            let written: Vec<(Option<&str>, IpAddr)> =
                rows.iter().map(|r| (r.0.as_deref(), r.2)).collect();
            assert_eq!(written, vec![(Some("uid:1000"), at(7))]);
        }

        let next = Arc::new(AppObservationStore::per_principal());
        let mem = memory(&next, rules, &table);
        assert_eq!(mem.warm_load(SystemTime::now()), 1);
        assert_eq!(plan_of(&next, "uid:1000", "firefox"), vec![ip(7)]);
        assert!(plan_of(&next, "uid:1001", "firefox").is_empty());
    }

    /// A machine-wide store keeps no owner, so it takes back only rows that
    /// have none.
    #[test]
    fn a_machine_wide_store_takes_only_ownerless_rows() {
        let table = Arc::new(FakeTable::default());
        let now = SystemTime::now();
        let persist = FakeTable::persist_fn(&table);
        persist(None, "messenger", &[at(1)], now);
        persist(Some("S-A"), "messenger", &[at(2)], now);

        let store = Arc::new(AppObservationStore::new());
        let mem = memory(&store, book(vec![app_rule("r1", "messenger.exe")]), &table);
        assert_eq!(mem.warm_load(now), 1);
        assert_eq!(store.ips_for_app("messenger.exe"), vec![ip(1)]);
    }
}
