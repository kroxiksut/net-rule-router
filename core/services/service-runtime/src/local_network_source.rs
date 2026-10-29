//! Where the "Local networks" list and the kill-switch exemptions get their
//! facts, independent of the OS.
//!
//! The decisions (which segment is exemptible, how a stored answer turns into
//! an exemption, when a public IPv6 prefix may open) are the pure functions
//! below; the Windows route coordinator and the planner of every other
//! platform both call them, so the two cannot drift apart. Only the reading of
//! the machine differs, and that sits behind [`LocalNetworkSource`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use nrr_domain::ipv4_network::Ipv4Network;
use nrr_platform_api::adapters::{preferred_display_name, AdapterEventSource, AdapterInfo};
use nrr_platform_api::route_table::RouteTablePort;
use nrr_platform_api::RouteEntry;
use nrr_shared::ip_block::IpBlock;

use crate::catch_all_exemptions::{bound_adapter, CatchAllExemptions};
use crate::fqdn_cache_lookup::FqdnCacheLookup;
use crate::per_sid_orchestrator::{
    PerSidBinding, PerSidPolicySnapshot, RoutePolicySource, RulesProvider,
};
use crate::route_coordinator::{
    LocalNetworkCandidates, LocalNetworkPolicy, LocalNetworkPolicyFn, PublicV6Network,
    SecondaryRouteCoordinator,
};
use crate::route_reconciler::exemptible_local_subnets;

/// The two readings the "Local networks" list is built from.
pub trait LocalNetworkSource: Send + Sync {
    /// The main link's connected private subnets and the host side of
    /// hypervisor adapters, each with its adapter's name and whether it is the
    /// main link's.
    fn discovered_local_networks(&self, sid: &str) -> Vec<(Ipv4Network, String, bool)>;

    /// The public IPv6 prefixes and too-wide segments the list shows beyond
    /// the discovered ones.
    fn local_network_candidates(&self, sid: &str) -> LocalNetworkCandidates;
}

impl LocalNetworkSource for SecondaryRouteCoordinator {
    fn discovered_local_networks(&self, sid: &str) -> Vec<(Ipv4Network, String, bool)> {
        SecondaryRouteCoordinator::discovered_local_networks(self, sid)
    }

    fn local_network_candidates(&self, sid: &str) -> LocalNetworkCandidates {
        SecondaryRouteCoordinator::local_network_candidates(self, sid)
    }
}

/// A host that can see no network: the list is empty.
pub struct NoLocalNetworks;

impl LocalNetworkSource for NoLocalNetworks {
    fn discovered_local_networks(&self, _sid: &str) -> Vec<(Ipv4Network, String, bool)> {
        Vec::new()
    }

    fn local_network_candidates(&self, _sid: &str) -> LocalNetworkCandidates {
        LocalNetworkCandidates::default()
    }
}

/// The links a reading is about, by interface index.
#[derive(Clone, Copy, Debug, Default)]
pub struct BoundLinks {
    pub primary: Option<u32>,
    pub secondary: Option<u32>,
}

/// The list's discovered half; see [`LocalNetworkSource::discovered_local_networks`].
pub fn discovered(
    routes: &[RouteEntry],
    adapters: &[AdapterInfo],
    links: BoundLinks,
) -> Vec<(Ipv4Network, String, bool)> {
    let name_of = |ifindex: u32| {
        adapters
            .iter()
            .find(|info| info.index == ifindex)
            .map(|info| preferred_display_name(info).to_string())
            .unwrap_or_default()
    };
    // The exemptible part only: a segment the enforcement refuses must not be
    // offered as something to keep reachable.
    let mut out: Vec<(Ipv4Network, String, bool)> = Vec::new();
    if let Some(primary) = links.primary {
        for (net, prefix) in exemptible_local_subnets(routes, primary).v4 {
            if let Some(network) = Ipv4Network::new(net, prefix) {
                out.push((network, name_of(primary), true));
            }
        }
    }
    for info in adapters
        .iter()
        .filter(|info| Some(info.index) != links.secondary)
        .filter(|info| nrr_platform_api::adapters::is_virtual_machine_adapter(info))
    {
        for (net, prefix) in exemptible_local_subnets(routes, info.index).v4 {
            let Some(network) = Ipv4Network::new(net, prefix) else {
                continue;
            };
            if out.iter().any(|(found, _, _)| *found == network) {
                continue;
            }
            out.push((network, preferred_display_name(info).to_string(), false));
        }
    }
    out
}

/// What the list shows beyond the private segments: the prefixes in
/// `public_v6`, the segments too wide to be local, and the main link's name.
pub fn candidates(
    routes: &[RouteEntry],
    adapters: &[AdapterInfo],
    primary: u32,
    public_v6: Vec<PublicV6Network>,
) -> LocalNetworkCandidates {
    LocalNetworkCandidates {
        public_v6,
        too_wide: exemptible_local_subnets(routes, primary).too_wide,
        adapter: adapters
            .iter()
            .find(|info| info.index == primary)
            .map(|info| preferred_display_name(info).to_string())
            .unwrap_or_default(),
    }
}

/// The main link's public IPv6 prefixes with what is decided about each.
/// Exempt only on the user's "yes", or on auto-accept outside the blanket
/// block (there it always asks), and never while a rule names something
/// inside. `names_rule` resolves the rule book, so it runs only for a prefix
/// that would otherwise open, or for every prefix when `for_display`.
pub fn public_v6_networks(
    routes: &[RouteEntry],
    primary: u32,
    answers: &[(IpBlock, bool)],
    auto_accept: bool,
    for_display: bool,
    names_rule: impl Fn(IpBlock) -> bool,
) -> Vec<PublicV6Network> {
    exemptible_local_subnets(routes, primary)
        .public_v6
        .into_iter()
        .filter_map(|(net, prefix)| IpBlock::new(IpAddr::V6(net), prefix))
        .map(|block| {
            let answer = answers.iter().find(|(b, _)| *b == block).map(|(_, a)| *a);
            let wanted = answer.unwrap_or(auto_accept);
            let names_rule = (wanted || for_display) && names_rule(block);
            PublicV6Network {
                block,
                allowed: wanted && !names_rule,
                decided: answer.is_some() || auto_accept,
                names_rule,
            }
        })
        .collect()
}

/// The opened prefixes as exemption pairs.
pub fn opened_pairs(networks: &[PublicV6Network]) -> Vec<(Ipv6Addr, u8)> {
    networks
        .iter()
        .filter(|n| n.allowed)
        .filter_map(|n| match n.block.network() {
            IpAddr::V6(net) => Some((net, n.block.prefix_len())),
            IpAddr::V4(_) => None,
        })
        .collect()
}

/// Lay the user's stored answers over `out`: networks they named are added,
/// networks they refused are removed, whether discovered or typed. An answer
/// given about an adapter carries over to whatever segment it holds now; a
/// refusal outranks a confirmation, the direction that never reopens what the
/// user closed.
pub fn apply_stored_answers(
    policy: &LocalNetworkPolicy,
    routes: &[RouteEntry],
    adapters: &[AdapterInfo],
    out: &mut Vec<(Ipv4Addr, u8)>,
) {
    let mut allowed = policy.allowed.clone();
    let mut refused = policy.refused.clone();
    for (adapter, allow) in &policy.adapter_answers {
        for info in adapters
            .iter()
            .filter(|info| preferred_display_name(info) == adapter)
        {
            // A "yes" about an adapter never reopens what the enforcement
            // refuses: the answer carries over to the exemptible part only.
            for (net, prefix) in exemptible_local_subnets(routes, info.index).v4 {
                let Some(network) = Ipv4Network::new(net, prefix) else {
                    continue;
                };
                if *allow {
                    allowed.push(network);
                } else {
                    refused.push(network);
                }
            }
        }
    }
    for network in &allowed {
        let pair = (network.network(), network.prefix_len());
        if !out.contains(&pair) {
            out.push(pair);
        }
    }
    // Compared as NETWORKS, not as pairs: the route table and the user's text
    // can spell the same network differently.
    out.retain(|(net, prefix)| {
        Ipv4Network::new(*net, *prefix).is_none_or(|candidate| !refused.contains(&candidate))
    });
}

/// The source for a platform without a route coordinator: it reads the route
/// table and links itself and resolves the user's bound links by name, the
/// way the planner does.
pub struct PolicyLocalNetworkSource {
    routes: Arc<dyn RouteTablePort>,
    adapters: Arc<dyn AdapterEventSource>,
    policy: Arc<dyn RoutePolicySource>,
    rules: Arc<dyn RulesProvider>,
    fqdn_cache: Arc<dyn FqdnCacheLookup>,
    answers: LocalNetworkPolicyFn,
}

impl PolicyLocalNetworkSource {
    pub fn new(
        routes: Arc<dyn RouteTablePort>,
        adapters: Arc<dyn AdapterEventSource>,
        policy: Arc<dyn RoutePolicySource>,
        rules: Arc<dyn RulesProvider>,
        fqdn_cache: Arc<dyn FqdnCacheLookup>,
        answers: LocalNetworkPolicyFn,
    ) -> Self {
        Self {
            routes,
            adapters,
            policy,
            rules,
            fqdn_cache,
            answers,
        }
    }

    fn read(&self) -> Option<(Vec<RouteEntry>, Vec<AdapterInfo>)> {
        let routes = self.routes.get_ip_forward_table().ok()?;
        let adapters = self.adapters.enumerate_all().ok()?;
        Some((routes, adapters))
    }

    fn links(adapters: &[AdapterInfo], policy: &PerSidPolicySnapshot) -> BoundLinks {
        let index_of = |binding: &Option<PerSidBinding>| {
            bound_adapter(adapters, binding.as_ref().map(|b| b.display_name.as_str()))
                .map(|a| a.index)
        };
        BoundLinks {
            primary: index_of(&policy.primary),
            secondary: index_of(&policy.secondary),
        }
    }

    /// Whether a rule of `sid` names an address inside a block. The book is
    /// resolved once, on the first block asked about.
    fn names_rule<'a>(&'a self, sid: &'a str) -> impl Fn(IpBlock) -> bool + 'a {
        let ownership = std::cell::OnceCell::new();
        move |block| {
            ownership
                .get_or_init(|| {
                    let rules = self.rules.active_rules_for(sid)?;
                    let snapshot = self.fqdn_cache.snapshot_for_compute();
                    let cache = crate::fqdn_cache_lookup::snapshot_or_live(
                        snapshot.as_deref(),
                        self.fqdn_cache.as_ref(),
                    );
                    Some(crate::address_ownership::AddressOwnership::resolve(
                        &rules.rule_book,
                        cache,
                    ))
                })
                .as_ref()
                .is_some_and(|o| o.names_inside(block))
        }
    }

    fn public_v6(
        &self,
        sid: &str,
        policy: &PerSidPolicySnapshot,
        routes: &[RouteEntry],
        primary: u32,
        for_display: bool,
    ) -> Vec<PublicV6Network> {
        let answers = (self.answers)(sid).answers_v6;
        // Under `everything` a silent answer would be a silent exemption.
        let auto_accept = policy.local_networks_auto_accept
            && !crate::per_sid_orchestrator::protects_everything(policy);
        public_v6_networks(
            routes,
            primary,
            &answers,
            auto_accept,
            for_display,
            self.names_rule(sid),
        )
    }

    /// Lay the stored answers over the exemptions a pass derived from its own
    /// reading of the machine.
    pub fn apply_to_exemptions(
        &self,
        sid: &str,
        policy: &PerSidPolicySnapshot,
        routes: &[RouteEntry],
        adapters: &[AdapterInfo],
        exemptions: &mut CatchAllExemptions,
    ) {
        apply_stored_answers(
            &(self.answers)(sid),
            routes,
            adapters,
            &mut exemptions.local_subnets,
        );
        let Some(primary) = Self::links(adapters, policy).primary else {
            return;
        };
        let opened = self.public_v6(sid, policy, routes, primary, false);
        for pair in opened_pairs(&opened) {
            if !exemptions.local_subnets_v6.contains(&pair) {
                exemptions.local_subnets_v6.push(pair);
            }
        }
    }
}

impl LocalNetworkSource for PolicyLocalNetworkSource {
    fn discovered_local_networks(&self, sid: &str) -> Vec<(Ipv4Network, String, bool)> {
        let (Some(policy), Some((routes, adapters))) = (self.policy.load_for_sid(sid), self.read())
        else {
            return Vec::new();
        };
        discovered(&routes, &adapters, Self::links(&adapters, &policy))
    }

    fn local_network_candidates(&self, sid: &str) -> LocalNetworkCandidates {
        let (Some(policy), Some((routes, adapters))) = (self.policy.load_for_sid(sid), self.read())
        else {
            return LocalNetworkCandidates::default();
        };
        let Some(primary) = Self::links(&adapters, &policy).primary else {
            return LocalNetworkCandidates::default();
        };
        let public_v6 = self.public_v6(sid, &policy, &routes, primary, true);
        candidates(&routes, &adapters, primary, public_v6)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::adapters::{IfOperStatus, InterfaceType};
    use nrr_platform_api::RouteTableRef;

    const PUBLIC_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 0);

    fn connected(destination: IpAddr, prefix: u8, ifindex: u32) -> RouteEntry {
        RouteEntry {
            destination,
            prefix_length: prefix,
            next_hop: match destination {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            },
            interface_index: ifindex,
            metric: 0,
            is_ours: false,
            table: RouteTableRef::Main,
        }
    }

    fn link(index: u32, name: &str) -> AdapterInfo {
        AdapterInfo {
            index,
            adapter_name: name.to_owned(),
            description: String::new(),
            friendly_name: name.to_owned(),
            mac: None,
            interface_type: InterfaceType::Ethernet,
            oper_status: IfOperStatus::Up,
            ipv4_addresses: Vec::new(),
            ipv6_addresses: Vec::new(),
            gateways: Vec::new(),
        }
    }

    fn home_routes() -> Vec<RouteEntry> {
        vec![
            connected(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24, 2),
            connected(IpAddr::V6(PUBLIC_V6), 64, 2),
            connected(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 0)), 24, 5),
        ]
    }

    #[test]
    fn the_main_links_connected_subnet_is_listed_and_the_tunnels_is_not() {
        let adapters = [link(2, "eth0"), link(5, "tun0")];
        let found = discovered(
            &home_routes(),
            &adapters,
            BoundLinks {
                primary: Some(2),
                secondary: Some(5),
            },
        );
        assert_eq!(
            found,
            vec![(
                Ipv4Network::parse("192.168.1.0/24").expect("net"),
                "eth0".to_owned(),
                true
            )]
        );
    }

    #[test]
    fn a_public_v6_prefix_is_a_candidate_that_opens_only_on_a_yes() {
        let routes = home_routes();
        let block = IpBlock::new(IpAddr::V6(PUBLIC_V6), 64).expect("block");

        let asked = public_v6_networks(&routes, 2, &[], false, true, |_| false);
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].block, block);
        assert!(!asked[0].allowed && !asked[0].decided);
        assert!(opened_pairs(&asked).is_empty());

        let yes = public_v6_networks(&routes, 2, &[(block, true)], false, false, |_| false);
        assert_eq!(opened_pairs(&yes), vec![(PUBLIC_V6, 64)]);

        let no = public_v6_networks(&routes, 2, &[(block, false)], true, false, |_| false);
        assert!(opened_pairs(&no).is_empty(), "a refusal beats auto-accept");
    }

    #[test]
    fn a_prefix_holding_a_rule_address_never_opens() {
        let block = IpBlock::new(IpAddr::V6(PUBLIC_V6), 64).expect("block");
        let listed = public_v6_networks(&home_routes(), 2, &[(block, true)], false, true, |_| true);
        assert!(listed[0].names_rule && !listed[0].allowed);
        assert!(opened_pairs(&listed).is_empty());
    }

    #[test]
    fn candidates_name_the_main_link() {
        let adapters = [link(2, "eth0")];
        let listed = candidates(&home_routes(), &adapters, 2, Vec::new());
        assert_eq!(listed.adapter, "eth0");
    }

    #[test]
    fn stored_answers_add_what_was_typed_and_remove_what_was_refused() {
        let adapters = [link(2, "eth0")];
        let mut out = vec![(Ipv4Addr::new(192, 168, 1, 0), 24)];
        let policy = LocalNetworkPolicy {
            allowed: vec![Ipv4Network::parse("10.9.0.0/16").expect("net")],
            refused: vec![Ipv4Network::parse("192.168.1.0/24").expect("net")],
            ..Default::default()
        };
        apply_stored_answers(&policy, &home_routes(), &adapters, &mut out);
        assert_eq!(out, vec![(Ipv4Addr::new(10, 9, 0, 0), 16)]);
    }

    #[test]
    fn an_answer_about_an_adapter_follows_the_segment_it_holds_now() {
        let adapters = [link(2, "eth0")];
        let mut out = Vec::new();
        let policy = LocalNetworkPolicy {
            adapter_answers: vec![("eth0".to_owned(), true)],
            ..Default::default()
        };
        apply_stored_answers(&policy, &home_routes(), &adapters, &mut out);
        assert_eq!(out, vec![(Ipv4Addr::new(192, 168, 1, 0), 24)]);
    }
}
