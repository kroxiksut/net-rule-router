//! Explicitly entered names may be checked without guessing an observed flow's name.

use super::*;
use crate::dns_resolver::UpstreamResolver;
use crate::per_sid_orchestrator::RulesProvider;
use nrr_platform_api::dns::{AddressFamily, DnsCacheReadPort};

pub type SiteResolverFactory = Arc<dyn Fn(&str) -> Option<Arc<dyn UpstreamResolver>> + Send + Sync>;

pub struct ManualSiteCheckWiring {
    pub rules: Arc<dyn RulesProvider>,
    pub primary_default: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    pub os_cache: Arc<dyn DnsCacheReadPort>,
    pub resolver_for: SiteResolverFactory,
    pub limits: Arc<dyn Fn(&str) -> crate::path_probe::ProbeLimits + Send + Sync>,
}

impl ManualSiteCheckWiring {
    pub fn production(
        state: Arc<Mutex<rusqlite::Connection>>,
        links: Arc<dyn EgressSources>,
        os_cache: Arc<dyn DnsCacheReadPort>,
        upstream: Arc<dyn Fn() -> Option<std::net::SocketAddr> + Send + Sync>,
    ) -> Self {
        let rules = Arc::new(
            crate::production_rules_provider::ProductionRulesProvider::new(Arc::clone(&state)),
        );
        let primary_default =
            crate::discovery_observation::stored_primary_default(Arc::clone(&state));
        let limits = crate::discovery_observation::stored_probe_limits(Arc::clone(&state));
        let resolver_for: SiteResolverFactory = Arc::new(move |sid| {
            let server = upstream()?;
            let sid = sid.to_owned();
            let policy = crate::dns_stack::stored_binding_egress_policy(
                Arc::clone(&state),
                Arc::new(move || Some(sid.clone())),
                None,
                None,
                Arc::clone(&links),
            );
            Some(Arc::new(
                crate::dns_resolver_ports::DirectUdpUpstreamResolver::new(server, PROBE_TIMEOUT, 1)
                    .with_egress(policy),
            ))
        });
        Self {
            rules,
            primary_default,
            os_cache,
            resolver_for,
            limits,
        }
    }

    pub(super) fn eligible(&self, sid: &str, host: &str, address: Option<Ipv4Addr>) -> bool {
        if !(self.primary_default)(sid) {
            return false;
        }
        let Some(snapshot) = self.rules.active_rules_for(sid) else {
            return false;
        };
        if snapshot
            .rule_book
            .primary
            .rules()
            .iter()
            .chain(snapshot.rule_book.secondary.rules())
            .any(|rule| rule.enabled && rule.app_match.is_some())
        {
            return false;
        }
        matches!(
            nrr_domain::decision_engine_input::match_sample(
                &snapshot.rule_book,
                Some(host),
                address.map(std::net::IpAddr::V4),
                None,
                nrr_domain::decision_matching::ZonePriorityPolicy::default(),
                nrr_domain::RouteBehaviorMode::PreferPrimary
            ),
            nrr_domain::decision_matching::RequestedRouteDecision::DefaultRoute { .. }
        )
    }

    pub(super) fn permits_primary_probe(
        &self,
        sid: &str,
        host: &str,
        address: Option<Ipv4Addr>,
    ) -> bool {
        let Some(snapshot) = self.rules.active_rules_for(sid) else {
            return false;
        };
        let decision = nrr_domain::decision_engine_input::match_sample(
            &snapshot.rule_book,
            Some(host),
            address.map(std::net::IpAddr::V4),
            None,
            nrr_domain::decision_matching::ZonePriorityPolicy::default(),
            nrr_domain::RouteBehaviorMode::PreferPrimary,
        );
        match decision {
            nrr_domain::decision_matching::RequestedRouteDecision::MatchedRoute { candidate } => {
                candidate.route_role == nrr_shared::RouteRole::Primary
                    && candidate.action == nrr_domain::RuleAction::Route
            }
            nrr_domain::decision_matching::RequestedRouteDecision::DefaultRoute { .. } => {
                self.eligible(sid, host, address)
            }
        }
    }

    pub(super) fn primary_probe_refusal(
        &self,
        sid: &str,
        host: &str,
        address: Option<Ipv4Addr>,
    ) -> Option<&'static str> {
        if self.permits_primary_probe(sid, host, address) {
            return None;
        }
        let Some(snapshot) = self.rules.active_rules_for(sid) else {
            return Some("rules-unavailable");
        };
        if snapshot
            .rule_book
            .primary
            .rules()
            .iter()
            .chain(snapshot.rule_book.secondary.rules())
            .any(|rule| rule.enabled && rule.app_match.is_some())
        {
            Some("application-context-required")
        } else {
            Some("route-context-required")
        }
    }

    pub(super) fn resolve(
        &self,
        sid: &str,
        host: &str,
        budget: Duration,
        network_allowed: bool,
    ) -> Vec<Ipv4Addr> {
        let started = Instant::now();
        if budget.is_zero() {
            return Vec::new();
        }
        if let Ok(entries) = self
            .os_cache
            .read_resolver_cache_matching(&|name| name.eq_ignore_ascii_case(host))
        {
            let found: Vec<_> = entries
                .into_iter()
                .take(1)
                .flat_map(|entry| entry.addresses)
                .filter_map(|ip| match ip {
                    std::net::IpAddr::V4(ip) => Some(ip),
                    _ => None,
                })
                .filter(|ip| !crate::net_filter::is_non_routable_v4(ip))
                .take(32)
                .collect();
            if !found.is_empty() {
                return found;
            }
        }
        if !network_allowed || !self.eligible(sid, host, None) {
            return Vec::new();
        }
        let Some(resolver) = (self.resolver_for)(sid) else {
            return Vec::new();
        };
        resolver
            .resolve_within(
                host,
                AddressFamily::Ipv4,
                budget.saturating_sub(started.elapsed()),
            )
            .map(|answer| {
                crate::dns_wire::only_v4(&answer.addresses)
                    .into_iter()
                    .filter(|ip| !crate::net_filter::is_non_routable_v4(ip))
                    .take(32)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Captured pre-redirect upstreams; never the service's own resolver address.
pub fn captured_dns_upstream() -> Option<std::net::SocketAddr> {
    crate::dns_stack::configured_dns_servers_now()
        .into_iter()
        .find(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .map(|ip| std::net::SocketAddr::new(ip, 53))
}

impl SiteChecker {
    pub fn attach_manual(&self, wiring: ManualSiteCheckWiring) {
        *self.manual.write().unwrap_or_else(|p| p.into_inner()) = Some(Arc::new(wiring));
    }

    pub(super) fn manual_pair(
        &self,
        sid: &str,
        site: &mut Examined,
        main: Option<Ipv4Addr>,
        additional: Option<Ipv4Addr>,
        deadline: Instant,
        manual: &ManualSiteCheckWiring,
    ) {
        let w = &self.wiring;
        let Some(engine) = &w.engine else {
            return;
        };
        let host = site.planned.name.as_str();
        let note = |state, reason| {
            engine.note_discovery(
                sid,
                Some(host),
                None,
                crate::auto_rules::DiscoveryDecision::new("probe", state, reason),
                std::time::SystemTime::now(),
            )
        };
        if site.route != "primary" || !manual.eligible(sid, host, site.address) {
            note("hidden", "already-covered");
            return;
        }
        let Some(target) = site.address else {
            note("deferred", "probe-no-address");
            return;
        };
        let Some(main) = main else {
            note("deferred", "probe-inconclusive");
            return;
        };
        if site.answer == "answered" {
            note("not-created", "primary-responds");
            return;
        }
        if site.answer != "silent" {
            note("deferred", "probe-inconclusive");
            return;
        }
        let Some(additional) = additional else {
            note("deferred", "secondary-unavailable");
            return;
        };
        for _ in 0..2 {
            if !manual.eligible(sid, host, Some(target)) {
                note("hidden", "already-covered");
                return;
            }
            let Some(timeout) =
                budget_left(deadline).map(|left| left.min((manual.limits)(sid).timeout))
            else {
                note("deferred", "probe-inconclusive");
                return;
            };
            match w.probe.probe_tls(target, host, Some(main), timeout) {
                PathVerdict::Answered => {
                    site.answer = "answered";
                    note("not-created", "primary-responds");
                    return;
                }
                PathVerdict::Silent => {}
                PathVerdict::Indeterminate => {
                    note("deferred", "probe-inconclusive");
                    return;
                }
            }
        }
        if !manual.eligible(sid, host, Some(target)) {
            note("hidden", "already-covered");
            return;
        }
        let Some(timeout) =
            budget_left(deadline).map(|left| left.min((manual.limits)(sid).timeout))
        else {
            note("deferred", "probe-inconclusive");
            return;
        };
        match w.probe.probe_tls(target, host, Some(additional), timeout) {
            PathVerdict::Answered => {
                use nrr_domain::companion_affinity::PrimaryHealthEvent;
                let stalls = crate::primary_stall_registry::global_primary_stalls();
                if let Some(report) = stalls.note_verified_tls(sid, host, false, 3) {
                    crate::primary_stall_registry::log_report(sid, &report);
                }
                for _ in 0..3 {
                    engine.note_primary_health(sid, host, PrimaryHealthEvent::Stalled);
                }
                let now = std::time::SystemTime::now();
                if engine.note_main_link_blocked_host(
                    sid,
                    host,
                    crate::navigation_registry::HostCounts::default(),
                    now,
                ) {
                    engine.note_secondary_reach(sid, host, true, now);
                }
            }
            PathVerdict::Silent => note("not-created", "secondary-failed"),
            PathVerdict::Indeterminate => note("deferred", "probe-inconclusive"),
        }
    }

    pub(super) fn record_manual_report(&self, sid: &str, report: &SiteCheckReport) {
        let Some(engine) = &self.wiring.engine else {
            return;
        };
        let Some(site) = report.names.iter().find(|name| name.role == "site") else {
            return;
        };
        let reason = match site.answer.as_str() {
            "no-address" => "probe-no-address",
            "https-unconfirmed" => "https-unconfirmed",
            "blocked" => "own-block",
            "route-down" if site.route == "secondary" => "secondary-unavailable",
            "route-down" | "unclear" | "certificate-untrusted" => "probe-inconclusive",
            _ => return,
        };
        engine.note_discovery(
            sid,
            Some(&site.name),
            None,
            crate::auto_rules::DiscoveryDecision::new("health", "not-created", reason),
            std::time::SystemTime::now(),
        );
    }
}
