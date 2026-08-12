//! Opt-in browser-history FQDN seeder.
//!
//! Closes the "visited before the service started" blind spot: the user consents
//! to a one-off import, we read the visited HOSTNAMES
//! ([`BrowserHistoryReadPort`]), keep only the ones a rule already matches, and
//! resolve + cache those so their suffix/zone permits compile before the first
//! block (the dzen.ru class).
//!
//! Privacy: only rule-MATCHING hostnames are ever resolved or cached — a site the
//! user visited that matches no rule is dropped in memory and never touches the
//! DB. The rule gate is the same [`rule_set_matches`] the DNS observer uses.
//!
//! Mechanism-free: the history read, the rule book, the resolver, and the cache
//! are injected as traits, so the core is unit-tested with fakes.

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use nrr_platform_api::browser_history::BrowserHistoryReadPort;
use nrr_platform_api::dns::DnsResolverPort;
use nrr_storage::dto::ResolutionEntry;
use nrr_storage::repository::CacheRepository;
use nrr_storage::resolution_source::StorageResolutionSource;

use crate::dns_observation_consumer::{rule_set_matches, ActiveSidFn};
use crate::net_filter::is_non_routable_v4;
use crate::per_sid_orchestrator::RulesProvider;
use crate::supervised_runtime::RouteRecomputeHook;

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

/// Reads the browser history, filters to rule hosts for the active user, resolves
/// them, and caches the results with source
/// [`StorageResolutionSource::BrowserHistorySeed`].
pub struct BrowserHistorySeeder {
    history: Arc<dyn BrowserHistoryReadPort>,
    rules: Arc<dyn RulesProvider>,
    active_sid: ActiveSidFn,
    resolver: Arc<dyn DnsResolverPort>,
    cache: Arc<Mutex<dyn CacheRepository + Send>>,
    recompute: Option<RouteRecomputeHook>,
}

impl BrowserHistorySeeder {
    pub fn new(
        history: Arc<dyn BrowserHistoryReadPort>,
        rules: Arc<dyn RulesProvider>,
        active_sid: ActiveSidFn,
        resolver: Arc<dyn DnsResolverPort>,
        cache: Arc<Mutex<dyn CacheRepository + Send>>,
    ) -> Self {
        Self {
            history,
            rules,
            active_sid,
            resolver,
            cache,
            recompute: None,
        }
    }

    /// Fire the route/WFP recompute after a successful seed so the new permits
    /// compile without waiting for the next periodic reconcile.
    pub fn with_recompute(mut self, hook: RouteRecomputeHook) -> Self {
        self.recompute = Some(hook);
        self
    }

    /// Run one opt-in seed pass. Returns the summary (also on partial failure —
    /// a browser or resolver error just lowers the counts, never errors the whole
    /// import). Triggers the recompute hook iff at least one host was cached.
    pub fn seed(&self, now: SystemTime) -> BrowserHistorySeedSummary {
        let mut summary = BrowserHistorySeedSummary::default();
        let Some(sid) = (self.active_sid)() else {
            return summary;
        };
        let Some(snapshot) = self.rules.active_rules_for(&sid) else {
            return summary;
        };
        // The read is principal-scoped: the service process is
        // LocalSystem, so the reader must resolve the ACTIVE USER's profile,
        // not its own (which has no browsers).
        let hostnames = match self.history.read_history_hostnames(&sid) {
            Ok(h) => h,
            Err(e) => {
                tracing::info!(
                    target: "nrr::browser-history",
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
            let Ok(record) = self.resolver.resolve_a(host) else {
                continue;
            };
            let routable: Vec<std::net::Ipv4Addr> = record
                .addresses
                .into_iter()
                .filter(|ip| !is_non_routable_v4(ip))
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
    use std::net::Ipv4Addr;

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
        fn resolve_a(&self, hostname: &str) -> Result<ResolvedRecord, DnsResolverError> {
            match self.map.get(hostname) {
                Some(ips) => Ok(ResolvedRecord {
                    canonical_hostname: hostname.to_string(),
                    addresses: ips.clone(),
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
                "dzen.ru".into(),     // matches zone .ru → resolve
                "avito.ru".into(),    // matches zone .ru → resolve
                "example.com".into(), // no rule → dropped
                "loopback.ru".into(), // matches, but resolves to loopback → not cached
            ],
        });
        let rules = Arc::new(ScriptedRules(CanonicalRuleSet::from_rules(vec![
            zone_rule("r-ru", "ru"),
        ])));
        let mut map = std::collections::HashMap::new();
        map.insert("dzen.ru".to_string(), vec![Ipv4Addr::new(5, 45, 202, 100)]);
        map.insert(
            "avito.ru".to_string(),
            vec![Ipv4Addr::new(178, 154, 131, 1)],
        );
        map.insert("loopback.ru".to_string(), vec![Ipv4Addr::new(127, 0, 0, 1)]);
        let resolver = Arc::new(FakeResolver { map });
        let cache = in_memory_cache();
        let seeder = BrowserHistorySeeder::new(
            history,
            rules,
            Arc::new(|| Some("S-1-5-21-A".to_string())),
            resolver,
            Arc::clone(&cache),
        );
        let s = seeder.seed(SystemTime::now());
        assert_eq!(s.visited, 4);
        assert_eq!(s.rule_matching, 3, "3 .ru hosts match; example.com dropped");
        assert_eq!(s.cached, 2, "dzen + avito cached; loopback filtered out");
    }

    #[test]
    fn no_active_sid_seeds_nothing() {
        let history = Arc::new(MockBrowserHistoryRead {
            hostnames: vec!["dzen.ru".into()],
        });
        let rules = Arc::new(ScriptedRules(CanonicalRuleSet::from_rules(vec![
            zone_rule("r-ru", "ru"),
        ])));
        let seeder = BrowserHistorySeeder::new(
            history,
            rules,
            Arc::new(|| None),
            Arc::new(FakeResolver {
                map: Default::default(),
            }),
            in_memory_cache(),
        );
        assert_eq!(
            seeder.seed(SystemTime::now()),
            BrowserHistorySeedSummary::default()
        );
    }
}
