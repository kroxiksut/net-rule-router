//! Runs the "does it answer on the main link?" pass for a principal's pending
//! suggestions.
//!
//! Joins four things that already exist: the pending suggestions (auto-rules
//! engine), the addresses behind their hostnames (FQDN cache), the main link's
//! own source address (route coordinator) and the bounded probe itself. The
//! verdict goes back through `note_primary_health` — the same channel observed
//! traffic uses — so the GUI has one story to tell regardless of how the
//! evidence was obtained.
//!
//! The pass runs on its own thread and answers the IPC request immediately:
//! eight addresses at a second and a half each is not something an IPC reply
//! may sit on, and the GUI already learns the outcome from the
//! suggestion-changed push.

use std::net::Ipv4Addr;
use std::sync::Arc;

use nrr_platform_api::adapters::AdapterInfo;
use nrr_platform_api::route_table::RouteTablePort;
use nrr_platform_api::types::RouteEntry;
use nrr_shared::ipc_payloads::AutoRuleCandidatesProbeResponse;

use crate::auto_rules::AutoRulesEngine;
use crate::fqdn_cache_lookup::FqdnCacheLookup;
use crate::ipc_handlers::providers::AutoRuleProbeRunner;
use crate::main_route_verdicts::{MainRouteVerdict, MainRouteVerdicts};
use crate::observed_host_names::ObservedHostNames;
use crate::path_probe::{PathProber, ProbeLimits, ProbeTarget};
use crate::per_sid_orchestrator::RoutePolicySource;
use crate::route_coordinator::SecondaryRouteCoordinator;

/// Port 443 is where a companion host lives in practice — these are CDN, media
/// and API endpoints. Probing the port the browser would use is the only answer
/// worth having; a reachable ICMP or port 80 would say something else.
const PROBE_PORT: u16 = 443;

/// Addresses taken from the observed-name memory per host. The pass stops at
/// the first one that answers either way, so a few only cover one that is down.
const MAX_OBSERVED_ADDRESSES: usize = 4;

/// Where a probe's packets leave from: the principal's main link and, when
/// one is bound, its additional link — each as the IPv4 address it carries.
pub trait EgressSources: Send + Sync {
    fn egress_source_ips(&self, sid: &str) -> (Option<Ipv4Addr>, Option<Ipv4Addr>);
}

impl EgressSources for SecondaryRouteCoordinator {
    fn egress_source_ips(&self, sid: &str) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
        self.resolve_egress_source_ips(sid)
    }
}

pub struct ProductionAutoRuleProbe {
    engine: Arc<AutoRulesEngine>,
    cache: Arc<dyn FqdnCacheLookup>,
    egress: Arc<dyn EgressSources>,
    prober: Arc<PathProber>,
    limits_for: Arc<dyn Fn(&str) -> ProbeLimits + Send + Sync>,
    /// Where a rule-host pass leaves its answers. `None` keeps the runner
    /// suggestion-only, exactly as before.
    verdicts: Option<Arc<MainRouteVerdicts>>,
    /// Prober for the second question — "would the tunnel reach it?". A
    /// SEPARATE instance on purpose: the prober suppresses a repeat of the same
    /// hostname, and sharing one would make the second pass skip every host the
    /// first had just asked about.
    secondary_prober: Option<Arc<PathProber>>,
    /// Where a suggestion's addresses come from when the FQDN cache has none —
    /// every host that makes an offer about itself, since no rule covers it.
    /// `None` keeps the runner cache-only.
    observed: Option<Arc<ObservedHostNames>>,
}

impl ProductionAutoRuleProbe {
    pub fn new(
        engine: Arc<AutoRulesEngine>,
        cache: Arc<dyn FqdnCacheLookup>,
        coordinator: Arc<SecondaryRouteCoordinator>,
        prober: Arc<PathProber>,
        limits_for: Arc<dyn Fn(&str) -> ProbeLimits + Send + Sync>,
    ) -> Self {
        Self::over(engine, cache, coordinator, prober, limits_for)
    }

    /// As [`Self::new`], with the egress addresses from any source — a
    /// platform without the route coordinator reads the stored bindings.
    pub fn over(
        engine: Arc<AutoRulesEngine>,
        cache: Arc<dyn FqdnCacheLookup>,
        egress: Arc<dyn EgressSources>,
        prober: Arc<PathProber>,
        limits_for: Arc<dyn Fn(&str) -> ProbeLimits + Send + Sync>,
    ) -> Self {
        Self {
            engine,
            cache,
            egress,
            prober,
            limits_for,
            verdicts: None,
            secondary_prober: None,
            observed: None,
        }
    }

    /// Wire the second pass: hosts the main link did not answer for are asked
    /// again over the additional route, and the answer is filed against the
    /// offer. Without it the runner behaves exactly as it did before.
    #[must_use]
    pub fn with_secondary_prober(mut self, prober: Arc<PathProber>) -> Self {
        self.secondary_prober = Some(prober);
        self
    }

    /// Wire the observed-name memory as the address source of last resort.
    #[must_use]
    pub fn with_observed_names(mut self, observed: Arc<ObservedHostNames>) -> Self {
        self.observed = Some(observed);
        self
    }

    /// Wire the store a rule-host pass writes its verdicts into; the rules list
    /// reads them back so the user sees what the check found.
    #[must_use]
    pub fn with_verdicts(mut self, verdicts: Arc<MainRouteVerdicts>) -> Self {
        self.verdicts = Some(verdicts);
        self
    }

    /// Probe targets for hosts the caller's rules already name.
    ///
    /// Same rule as for suggestions: a host with nothing cached is skipped
    /// rather than resolved here — resolving would send a query the user did
    /// not ask for, and the answer would arrive after this pass.
    fn rule_targets(&self, hostnames: &[String]) -> Vec<ProbeTarget> {
        hostnames
            .iter()
            .map(|h| h.trim().trim_start_matches("*.").to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .filter_map(|hostname| {
                let addresses = crate::dns_wire::only_v4(&self.cache.ips_for_hostname(&hostname));
                (!addresses.is_empty()).then_some(ProbeTarget {
                    hostname,
                    addresses,
                })
            })
            .collect()
    }

    /// The hosts to examine: the named suggestions, or every pending one.
    ///
    /// Addresses come from the FQDN cache, else from the observed-name memory.
    /// A suggestion neither knows is skipped rather than resolved here:
    /// resolving would send a query the user did not ask for, and the answer
    /// would arrive too late for this pass anyway.
    fn targets(&self, sid: &str, ids: &[String]) -> Vec<ProbeTarget> {
        self.engine
            .candidates(sid)
            .into_iter()
            .filter(|c| ids.is_empty() || ids.contains(&c.id))
            .filter_map(|c| {
                let hostname = c.proposed_match.trim_start_matches("*.").to_string();
                let mut addresses =
                    crate::dns_wire::only_v4(&self.cache.ips_for_hostname(&hostname));
                if addresses.is_empty() {
                    if let Some(observed) = &self.observed {
                        addresses = observed.addresses_under(&hostname, MAX_OBSERVED_ADDRESSES);
                    }
                }
                (!addresses.is_empty()).then_some(ProbeTarget {
                    hostname,
                    addresses,
                })
            })
            .collect()
    }
}

impl AutoRuleProbeRunner for ProductionAutoRuleProbe {
    fn probe(
        &self,
        sid: &str,
        ids: &[String],
        rule_hostnames: &[String],
    ) -> AutoRuleCandidatesProbeResponse {
        let limits = (self.limits_for)(sid);
        // Rule hosts and suggestions are the same question over the same
        // mechanism; only where the verdict is filed differs.
        let rules_pass = !rule_hostnames.is_empty();
        let targets = if rules_pass {
            self.rule_targets(rule_hostnames)
        } else {
            self.targets(sid, ids)
        };
        if targets.is_empty() {
            return AutoRuleCandidatesProbeResponse::default();
        }
        let over_limit = targets.len().saturating_sub(limits.max_targets) as u32;
        let accepted = targets.len().min(limits.max_targets) as u32;
        // The main link's own address — without it the OS would route by the
        // pin, which points at the tunnel and would answer a different question.
        let (source, secondary_source) = self.egress.egress_source_ips(sid);
        let engine = Arc::clone(&self.engine);
        let prober = Arc::clone(&self.prober);
        let sid_owned = sid.to_string();
        let verdicts = self.verdicts.clone();
        // The second question is only worth asking about SUGGESTIONS, and only
        // when there is a tunnel to ask over.
        let secondary = (!rules_pass)
            .then(|| self.secondary_prober.clone())
            .flatten()
            .zip(secondary_source);
        let targets_for_second = targets.clone();
        let engine_for_second = Arc::clone(&self.engine);
        let sid_for_second = sid.to_string();
        let spawned = std::thread::Builder::new()
            .name("nrr-main-link-probe".into())
            .spawn(move || {
                use nrr_domain::companion_affinity::PrimaryHealthEvent;
                let report = move |hostname: &str, answered: bool| {
                    if rules_pass {
                        // A rule's own address: the answer belongs beside the
                        // rule, not in the suggestion engine's health signal —
                        // feeding it there would let a check the user ran on
                        // their own rules reshape what gets suggested.
                        if let Some(store) = verdicts.as_ref() {
                            store.record(
                                &sid_owned,
                                hostname,
                                if answered {
                                    MainRouteVerdict::Answered
                                } else {
                                    MainRouteVerdict::Silent
                                },
                                std::time::Instant::now(),
                            );
                        }
                        return;
                    }
                    engine.note_primary_health(
                        &sid_owned,
                        hostname,
                        if answered {
                            PrimaryHealthEvent::Completed
                        } else {
                            PrimaryHealthEvent::Stalled
                        },
                    );
                };
                let unanswered = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
                let report_and_collect = {
                    let unanswered = Arc::clone(&unanswered);
                    move |hostname: &str, answered: bool| {
                        if !answered {
                            unanswered
                                .lock()
                                .unwrap_or_else(|p| p.into_inner())
                                .push(hostname.to_string());
                        }
                        report(hostname, answered);
                    }
                };
                let summary = prober.run_pass(
                    &targets,
                    PROBE_PORT,
                    source,
                    limits,
                    std::time::Instant::now(),
                    &report_and_collect,
                );
                tracing::info!(
                    target: "nrr::auto-rules",
                    msg_key = "prod-autorule-main-link-checked",
                    answered = summary.answered,
                    silent = summary.silent,
                    indeterminate = summary.indeterminate,
                    skipped_recent = summary.skipped_recent,
                    skipped_over_limit = summary.skipped_over_limit,
                    source = ?source,
                    "checked whether the suggested addresses answer on the main link (requested by the user)",
                );
                let Some((secondary_prober, secondary_source)) = secondary else {
                    return;
                };
                // Only the hosts the main link could not reach: for the rest
                // the offer is already answered, and asking the tunnel would
                // send traffic there for a question nobody has.
                let silent: Vec<String> = unanswered
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clone();
                if silent.is_empty() {
                    return;
                }
                let second_targets: Vec<ProbeTarget> = targets_for_second
                    .into_iter()
                    .filter(|t| silent.contains(&t.hostname))
                    .collect();
                let record = move |hostname: &str, answered: bool| {
                    engine_for_second.note_secondary_reach(
                        &sid_for_second,
                        hostname,
                        answered,
                        std::time::SystemTime::now(),
                    );
                };
                let second = secondary_prober.run_pass(
                    &second_targets,
                    PROBE_PORT,
                    Some(secondary_source),
                    limits,
                    std::time::Instant::now(),
                    &record,
                );
                tracing::info!(
                    target: "nrr::auto-rules",
                    msg_key = "prod-autorule-secondary-reach-checked",
                    answered = second.answered,
                    silent = second.silent,
                    indeterminate = second.indeterminate,
                    "checked whether the additional route reaches the hosts the main link did not",
                );
            });
        if let Err(e) = spawned {
            tracing::warn!(
                target: "nrr::auto-rules",
                msg_key = "prod-autorule-probe-spawn-failed",
                error = %e,
                "could not start the main-link probe pass",
            );
            return AutoRuleCandidatesProbeResponse::default();
        }
        AutoRuleCandidatesProbeResponse {
            accepted,
            over_limit,
        }
    }
}

/// [`EgressSources`] from the principal's stored bindings and the live links,
/// for a platform without the route coordinator. A link answers to a binding
/// by name; an unbound main link is derived from the default route exactly as
/// the coordinator derives it.
pub struct StoredBindingEgress {
    policy: Arc<dyn RoutePolicySource>,
    api: Arc<dyn RouteTablePort>,
}

impl StoredBindingEgress {
    pub fn new(policy: Arc<dyn RoutePolicySource>, api: Arc<dyn RouteTablePort>) -> Self {
        Self { policy, api }
    }
}

impl EgressSources for StoredBindingEgress {
    fn egress_source_ips(&self, sid: &str) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
        let Some(policy) = self.policy.load_for_sid(sid) else {
            return (None, None);
        };
        let Ok(links) = self.api.get_adapter_infos() else {
            return (None, None);
        };
        let routes = self.api.get_ip_forward_table().unwrap_or_default();
        egress_sources_from(
            policy.primary.as_ref().map(|b| b.display_name.as_str()),
            policy.secondary.as_ref().map(|b| b.display_name.as_str()),
            &links,
            &routes,
        )
    }
}

/// The address each bound link carries. A bound link that is absent yields
/// `None` — the probe then does not run rather than measure another path.
pub fn egress_sources_from(
    primary: Option<&str>,
    secondary: Option<&str>,
    links: &[AdapterInfo],
    routes: &[RouteEntry],
) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
    let named = |name: &str| {
        links
            .iter()
            .find(|l| l.friendly_name == name || l.adapter_name == name)
    };
    let secondary_link = secondary.and_then(named);
    let primary_link = match primary {
        Some(name) => named(name),
        None => {
            let ours: Vec<u32> = secondary_link.map(|l| l.index).into_iter().collect();
            let foreign = crate::route_coordinator::foreign_tunnel_indexes(links, &ours, routes);
            crate::route_coordinator::derive_primary_target(
                routes,
                secondary_link.map_or(0, |l| l.index),
                &foreign,
            )
            .and_then(|t| links.iter().find(|l| l.index == t.interface_index))
        }
    };
    let address = |link: Option<&AdapterInfo>| link.and_then(|l| l.ipv4_addresses.first().copied());
    (address(primary_link), address(secondary_link))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::adapters::{IfOperStatus, InterfaceType};
    use std::net::IpAddr;

    fn link(name: &str, index: u32, address: [u8; 4]) -> AdapterInfo {
        AdapterInfo {
            index,
            adapter_name: name.into(),
            description: name.into(),
            friendly_name: name.into(),
            mac: None,
            interface_type: InterfaceType::Ethernet,
            oper_status: IfOperStatus::Up,
            ipv4_addresses: vec![Ipv4Addr::from(address)],
            ipv6_addresses: Vec::new(),
            gateways: Vec::new(),
        }
    }

    fn default_via(index: u32, gateway: [u8; 4], metric: u32) -> RouteEntry {
        RouteEntry {
            destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            prefix_length: 0,
            next_hop: IpAddr::V4(Ipv4Addr::from(gateway)),
            interface_index: index,
            metric,
            is_ours: false,
            table: nrr_platform_api::RouteTableRef::Main,
        }
    }

    fn machine() -> (Vec<AdapterInfo>, Vec<RouteEntry>) {
        (
            vec![
                link("eth0", 2, [192, 0, 2, 10]),
                link("wlan0", 3, [192, 0, 2, 20]),
                link("tun0", 9, [198, 51, 100, 7]),
            ],
            vec![
                default_via(9, [198, 51, 100, 1], 1),
                default_via(3, [192, 0, 2, 1], 600),
                default_via(2, [192, 0, 2, 1], 100),
            ],
        )
    }

    #[test]
    fn bound_links_answer_by_name() {
        let (links, routes) = machine();
        assert_eq!(
            egress_sources_from(Some("wlan0"), Some("tun0"), &links, &routes),
            (
                Some(Ipv4Addr::new(192, 0, 2, 20)),
                Some(Ipv4Addr::new(198, 51, 100, 7))
            )
        );
    }

    /// The common setup binds only the tunnel: the main link is the best
    /// default route that is not the tunnel's.
    #[test]
    fn an_unbound_main_link_is_the_default_route_off_the_tunnel() {
        let (links, routes) = machine();
        assert_eq!(
            egress_sources_from(None, Some("tun0"), &links, &routes),
            (
                Some(Ipv4Addr::new(192, 0, 2, 10)),
                Some(Ipv4Addr::new(198, 51, 100, 7))
            )
        );
    }

    /// A bound link that is gone must not be swapped for another one: the
    /// answer would be about a path the user did not name.
    #[test]
    fn a_missing_bound_link_yields_no_address() {
        let (links, routes) = machine();
        assert_eq!(
            egress_sources_from(Some("eth9"), Some("tun9"), &links, &routes),
            (None, None)
        );
    }
}
