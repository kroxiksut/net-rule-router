//! Opt-in browser-history FQDN seeder.
//!
//! Closes the "visited before the service started" blind spot: the user consents
//! to a one-off import, we read the visited HOSTNAMES
//! ([`BrowserHistoryReadPort`]), keep only the ones a rule already matches, and
//! resolve + cache those so their suffix/zone permits compile before the first
//! block (the visited-but-unruled class).
//!
//! Privacy: only rule-MATCHING hostnames are ever resolved or cached — a site the
//! user visited that matches no rule is dropped in memory and never touches the
//! DB. The rule gate is the same [`rule_set_matches`] the DNS observer uses.
//!
//! Mechanism-free: the history read, the rule book, the resolver, and the cache
//! are injected as traits, so the core is unit-tested with fakes.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use nrr_platform_api::browser_history::BrowserHistoryReadPort;
use nrr_platform_api::dns::DnsResolverPort;
use nrr_storage::dto::ResolutionEntry;
use nrr_storage::repository::CacheRepository;
use nrr_storage::resolution_source::StorageResolutionSource;

use crate::dns_observation_consumer::rule_set_matches;
use crate::net_filter::is_non_routable;
use crate::per_sid_orchestrator::RulesProvider;
use crate::supervised_runtime::RouteRecomputeHook;
use nrr_platform_api::dns::AddressFamily;

/// Outcome of one seed pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BrowserHistorySeedSummary {
    /// Distinct visited hostnames read from the browsers.
    pub visited: usize,
    /// How many of those matched an active rule (the only ones we resolve).
    pub rule_matching: usize,
    /// How many rule-matching hosts resolved to a routable IP and were cached.
    pub cached: usize,
}

/// Max rule-matching hostnames resolved in one pass — a backstop so a huge
/// history cannot turn into an unbounded resolve storm. Rule-matching hosts are
/// already a small subset, so this is generous.
const MAX_SEED_HOSTS: usize = 1000;

/// Reads one principal's browser history, filters to that principal's rule
/// hosts, resolves them, and caches the results with source
/// [`StorageResolutionSource::BrowserHistorySeed`].
///
/// The principal is always named by the caller — the requester's own SID, never
/// "whoever is active": the consent covers the consenting user's history only.
pub struct BrowserHistorySeeder {
    history: Arc<dyn BrowserHistoryReadPort>,
    rules: Arc<dyn RulesProvider>,
    resolver: Arc<dyn DnsResolverPort>,
    cache: Arc<Mutex<dyn CacheRepository + Send>>,
    recompute: Option<RouteRecomputeHook>,
    /// Principals with a pass in flight. A second request for the same user
    /// would read the same history and resolve the same hosts twice over.
    in_flight: Mutex<HashSet<String>>,
}

/// One claimed seed pass for a principal. The claim is released when this is
/// dropped, whether or not [`Self::run`] was reached — a worker that failed to
/// spawn must not leave the user locked out.
pub struct SeedRun {
    seeder: Arc<BrowserHistorySeeder>,
    sid: String,
}

impl SeedRun {
    pub fn sid(&self) -> &str {
        &self.sid
    }

    pub fn run(self, now: SystemTime) -> BrowserHistorySeedSummary {
        self.seeder.seed_for(&self.sid, now)
    }
}

impl Drop for SeedRun {
    fn drop(&mut self) {
        self.seeder
            .in_flight
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.sid);
    }
}

impl BrowserHistorySeeder {
    pub fn new(
        history: Arc<dyn BrowserHistoryReadPort>,
        rules: Arc<dyn RulesProvider>,
        resolver: Arc<dyn DnsResolverPort>,
        cache: Arc<Mutex<dyn CacheRepository + Send>>,
    ) -> Self {
        Self {
            history,
            rules,
            resolver,
            cache,
            recompute: None,
            in_flight: Mutex::new(HashSet::new()),
        }
    }

    /// Fire the route/WFP recompute after a successful seed so the new permits
    /// compile without waiting for the next periodic reconcile.
    pub fn with_recompute(mut self, hook: RouteRecomputeHook) -> Self {
        self.recompute = Some(hook);
        self
    }

    /// Claim the single seed slot for `sid`; `None` while a pass for that
    /// principal is still running.
    pub fn try_begin(self: &Arc<Self>, sid: &str) -> Option<SeedRun> {
        let mut in_flight = self.in_flight.lock().unwrap_or_else(|p| p.into_inner());
        if !in_flight.insert(sid.to_owned()) {
            return None;
        }
        Some(SeedRun {
            seeder: Arc::clone(self),
            sid: sid.to_owned(),
        })
    }

    /// One seed pass for `sid`. Returns the summary (also on partial failure —
    /// a browser or resolver error just lowers the counts, never errors the whole
    /// import). Triggers the recompute hook iff at least one host was cached.
    fn seed_for(&self, sid: &str, now: SystemTime) -> BrowserHistorySeedSummary {
        let mut summary = BrowserHistorySeedSummary::default();
        let Some(snapshot) = self.rules.active_rules_for(sid) else {
            return summary;
        };
        // The service runs as LocalSystem, whose own profile has no browsers:
        // the reader resolves this principal's profile.
        let hostnames = match self.history.read_history_hostnames(sid) {
            Ok(h) => h,
            Err(e) => {
                tracing::info!(
                    target: "nrr::browser-history",
                    msg_key = "browserhistseed-read-failed",
                    error = %e,
                    "browser-history seed: nothing read",
                );
                return summary;
            }
        };
        summary.visited = hostnames.len();

        let matching: Vec<String> = hostnames
            .into_iter()
            .filter(|h| {
                rule_set_matches(h, &snapshot.rule_book.primary)
                    || rule_set_matches(h, &snapshot.rule_book.secondary)
            })
            .take(MAX_SEED_HOSTS)
            .collect();
        summary.rule_matching = matching.len();

        for host in &matching {
            let Ok(record) = self.resolver.resolve(host, AddressFamily::Ipv4) else {
                continue;
            };
            let routable: Vec<std::net::IpAddr> = record
                .addresses
                .iter()
                .copied()
                .filter(|ip| !is_non_routable(ip))
                .collect();
            if routable.is_empty() {
                continue;
            }
            let entry = ResolutionEntry {
                canonical_hostname: host.clone(),
                raw_hostname_sample: None,
                resolved_ips: routable,
                ttl_seconds: record.ttl_seconds,
                source: StorageResolutionSource::BrowserHistorySeed,
                resolved_at: now,
                active_revision_id: None,
            };
            let guard = self.cache.lock().unwrap_or_else(|p| p.into_inner());
            if guard.upsert_resolution(entry).is_ok() {
                summary.cached += 1;
            }
        }

        if summary.cached > 0 {
            tracing::info!(
                target: "nrr::browser-history",
                msg_key = "browserhistseed-cached",
                visited = summary.visited,
                rule_matching = summary.rule_matching,
                cached = summary.cached,
                "browser-history seed cached rule-matching hosts (opt-in import)",
            );
            if let Some(hook) = self.recompute.as_ref() {
                hook();
            }
        }
        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_domain::canonical::{
        CanonicalAddressMatch, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet,
    };
    use nrr_domain::{RouteBehaviorMode, RuleId};
    use nrr_platform_api::browser_history::MockBrowserHistoryRead;
    use nrr_platform_api::dns::{DnsResolverError, ResolvedRecord};
    use std::net::{IpAddr, Ipv4Addr};

    use crate::per_sid_orchestrator::ActiveRulesSnapshot;

    struct ScriptedRules(CanonicalRuleSet);
    impl RulesProvider for ScriptedRules {
        fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
            Some(ActiveRulesSnapshot {
                rule_book: CanonicalRuleBook {
                    primary: self.0.clone(),
                    secondary: CanonicalRuleSet::from_rules(vec![]),
                },
                behavior_mode: RouteBehaviorMode::PreferPrimary,
            })
        }
    }

    struct FakeResolver {
        map: std::collections::HashMap<String, Vec<Ipv4Addr>>,
    }
    impl DnsResolverPort for FakeResolver {
        fn resolve(
            &self,
            hostname: &str,
            _family: AddressFamily,
        ) -> Result<ResolvedRecord, DnsResolverError> {
            match self.map.get(hostname) {
                Some(ips) => Ok(ResolvedRecord {
                    canonical_hostname: hostname.to_string(),
                    addresses: ips.iter().copied().map(IpAddr::V4).collect(),
                    ttl_seconds: Some(300),
                }),
                None => Err(DnsResolverError::NxDomain {
                    hostname: hostname.to_string(),
                }),
            }
        }
    }

    fn zone_rule(id: &str, suffix: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::Zone(suffix.into())),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }
    }

    fn in_memory_cache() -> Arc<Mutex<dyn CacheRepository + Send>> {
        use nrr_domain::decision_lookup::FreshnessThresholds;
        use nrr_storage::migration::SqliteMigrationRunner;
        use nrr_storage::repository::MigrationRunner;
        use nrr_storage::store::SqliteCacheStore;
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let runner = SqliteMigrationRunner::for_cache_db(conn);
        runner.run_pending_migrations().unwrap();
        Arc::new(Mutex::new(SqliteCacheStore::new(
            runner.into_connection(),
            FreshnessThresholds::default_production(),
        )))
    }

    #[test]
    fn seeds_only_rule_matching_hosts_and_caches_routable() {
        let history = Arc::new(MockBrowserHistoryRead {
            hostnames: vec![
                "feed.example".into(),     // matches zone .example → resolve
                "shop.example".into(),     // matches the zone → resolve
                "example.com".into(),      // no rule → dropped
                "loopback.example".into(), // matches, but resolves to loopback → not cached
            ],
        });
        let rules = Arc::new(ScriptedRules(CanonicalRuleSet::from_rules(vec![
            zone_rule("r-zone", "example"),
        ])));
        let mut map = std::collections::HashMap::new();
        map.insert(
            "feed.example".to_string(),
            vec![Ipv4Addr::new(203, 0, 113, 100)],
        );
        map.insert(
            "shop.example".to_string(),
            vec![Ipv4Addr::new(203, 0, 113, 101)],
        );
        map.insert(
            "loopback.example".to_string(),
            vec![Ipv4Addr::new(127, 0, 0, 1)],
        );
        let resolver = Arc::new(FakeResolver { map });
        let cache = in_memory_cache();
        let seeder = BrowserHistorySeeder::new(history, rules, resolver, Arc::clone(&cache));
        let s = seeder.seed_for("S-1-5-21-A", SystemTime::now());
        assert_eq!(s.visited, 4);
        assert_eq!(
            s.rule_matching, 3,
            "3 zone hosts match; example.com dropped"
        );
        assert_eq!(s.cached, 2, "two hosts cached; loopback filtered out");
    }

    /// Records whose history was asked for.
    #[derive(Default)]
    struct RecordingHistory {
        asked: Mutex<Vec<String>>,
    }
    impl BrowserHistoryReadPort for RecordingHistory {
        fn read_history_hostnames(
            &self,
            principal: &str,
        ) -> Result<Vec<String>, nrr_platform_api::browser_history::BrowserHistoryError> {
            self.asked
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(principal.to_owned());
            Ok(vec!["feed.example".into()])
        }
    }

    /// Rules for exactly one principal.
    struct OnePrincipalRules(&'static str);
    impl RulesProvider for OnePrincipalRules {
        fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
            None
        }
        fn active_rules_for(&self, principal: &str) -> Option<ActiveRulesSnapshot> {
            (principal == self.0).then(|| ActiveRulesSnapshot {
                rule_book: CanonicalRuleBook {
                    primary: CanonicalRuleSet::from_rules(vec![zone_rule("r-zone", "example")]),
                    secondary: CanonicalRuleSet::from_rules(vec![]),
                },
                behavior_mode: RouteBehaviorMode::PreferPrimary,
            })
        }
    }

    fn resolver_for_feed() -> Arc<FakeResolver> {
        let mut map = std::collections::HashMap::new();
        map.insert(
            "feed.example".to_string(),
            vec![Ipv4Addr::new(203, 0, 113, 100)],
        );
        Arc::new(FakeResolver { map })
    }

    /// The consent is the requester's: user B's import must read B's profile
    /// against B's rules, whoever else is signed in.
    #[test]
    fn a_pass_reads_the_named_principals_history_and_rules_only() {
        let history = Arc::new(RecordingHistory::default());
        let seeder = Arc::new(BrowserHistorySeeder::new(
            Arc::clone(&history) as Arc<dyn BrowserHistoryReadPort>,
            Arc::new(OnePrincipalRules("S-1-5-21-B")),
            resolver_for_feed(),
            in_memory_cache(),
        ));
        let run = seeder.try_begin("S-1-5-21-B").expect("slot free");
        let s = run.run(SystemTime::now());
        assert_eq!(s.cached, 1);
        assert_eq!(
            history.asked.lock().expect("asked").as_slice(),
            &["S-1-5-21-B".to_string()]
        );
    }

    #[test]
    fn a_principal_without_rules_seeds_nothing_and_reads_no_history() {
        let history = Arc::new(RecordingHistory::default());
        let seeder = Arc::new(BrowserHistorySeeder::new(
            Arc::clone(&history) as Arc<dyn BrowserHistoryReadPort>,
            Arc::new(OnePrincipalRules("S-1-5-21-A")),
            resolver_for_feed(),
            in_memory_cache(),
        ));
        let s = seeder
            .try_begin("S-1-5-21-B")
            .expect("slot free")
            .run(SystemTime::now());
        assert_eq!(s, BrowserHistorySeedSummary::default());
        assert!(history.asked.lock().expect("asked").is_empty());
    }

    #[test]
    fn one_pass_per_principal_at_a_time() {
        let seeder = Arc::new(BrowserHistorySeeder::new(
            Arc::new(RecordingHistory::default()),
            Arc::new(OnePrincipalRules("S-1-5-21-A")),
            resolver_for_feed(),
            in_memory_cache(),
        ));
        let first = seeder.try_begin("S-1-5-21-A").expect("slot free");
        assert!(
            seeder.try_begin("S-1-5-21-A").is_none(),
            "a second pass for the same user is refused while one runs"
        );
        let other = seeder.try_begin("S-1-5-21-B");
        assert!(other.is_some(), "another user's pass is independent");
        drop(first);
        assert!(
            seeder.try_begin("S-1-5-21-A").is_some(),
            "the slot is released when the pass ends"
        );
    }
}
