//! What the corporate tunnel beside ours carries, published once and read from
//! anywhere.
//!
//! The route coordinator names the foreign tunnels and their networks; the DNS
//! layer reports which adapter claims which namespace, and only a claim made
//! by a link the coordinator calls foreign counts. The fake-IP answerers and
//! the connection observer must stay out of both: a virtual address for such
//! a name points the caller at our TUN, and a pin for such an address steals
//! it from the tunnel that owns it.
//!
//! Readers sit on the DNS answer path, so the common case (no corporate
//! tunnel) costs one atomic load, and a read otherwise is one shared lock.

use std::cmp::Ordering as CmpOrdering;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

use nrr_domain::ipv4_network::Ipv4Network;
use nrr_platform_api::adapters::AdapterInfo;
use nrr_platform_api::types::RouteEntry;

/// Most networks and namespaces kept; a table past this is not a tunnel's.
const MAX_ENTRIES: usize = 1024;

/// One immutable reading of what the foreign tunnels own.
#[derive(Debug, Default)]
pub struct ForeignTunnelFacts {
    /// Disjoint, sorted `(first, last)` address ranges.
    ranges: Vec<(u32, u32)>,
    /// Lower-case, sorted by bytes, no dots at the ends.
    namespaces: Vec<String>,
}

impl ForeignTunnelFacts {
    fn new(networks: &[Ipv4Network], namespaces: Vec<String>) -> Self {
        let mut spans: Vec<(u32, u32)> = networks
            .iter()
            .map(|net| {
                let first = u32::from(net.network());
                let last = first
                    | u32::MAX
                        .checked_shr(u32::from(net.prefix_len()))
                        .unwrap_or(0);
                (first, last)
            })
            .collect();
        spans.sort_unstable();
        let mut ranges: Vec<(u32, u32)> = Vec::with_capacity(spans.len());
        for (first, last) in spans {
            match ranges.last_mut() {
                Some(prev) if first <= prev.1.saturating_add(1) => prev.1 = prev.1.max(last),
                _ => ranges.push((first, last)),
            }
        }
        Self { ranges, namespaces }
    }

    fn is_empty(&self) -> bool {
        self.ranges.is_empty() && self.namespaces.is_empty()
    }

    /// Does a foreign tunnel carry `ip`?
    #[must_use]
    pub fn carries(&self, ip: Ipv4Addr) -> bool {
        let ip = u32::from(ip);
        let after = self.ranges.partition_point(|&(first, _)| first <= ip);
        after
            .checked_sub(1)
            .and_then(|i| self.ranges.get(i))
            .is_some_and(|&(_, last)| last >= ip)
    }

    /// Does a foreign tunnel carry any of `ips`?
    #[must_use]
    pub fn carries_any(&self, ips: &[Ipv4Addr]) -> bool {
        !self.ranges.is_empty() && ips.iter().any(|ip| self.carries(*ip))
    }

    /// Does a foreign tunnel's namespace hold `hostname`, on a label boundary?
    /// Each label-boundary tail is looked up; nothing is allocated.
    #[must_use]
    pub fn claims_name(&self, hostname: &str) -> bool {
        if self.namespaces.is_empty() {
            return false;
        }
        let mut tail = hostname.trim().trim_end_matches('.').as_bytes();
        loop {
            if self
                .namespaces
                .binary_search_by(|ns| cmp_lowered(ns.as_bytes(), tail))
                .is_ok()
            {
                return true;
            }
            match tail.iter().position(|&b| b == b'.') {
                Some(dot) => tail = &tail[dot + 1..],
                None => return false,
            }
        }
    }
}

/// `namespace` against `tail` lower-cased, in the byte order the namespaces
/// are sorted by.
fn cmp_lowered(namespace: &[u8], tail: &[u8]) -> CmpOrdering {
    namespace
        .iter()
        .copied()
        .cmp(tail.iter().map(u8::to_ascii_lowercase))
}

#[derive(Default)]
struct Published {
    facts: Arc<ForeignTunnelFacts>,
    networks: Vec<Ipv4Network>,
    /// The coordinator's foreign tunnels as `(interface index, adapter name)`;
    /// `None` until it has named them, which no claim survives.
    tunnels: Option<Vec<(u32, String)>>,
    /// Namespace claims as `(adapter name, suffix)`, whatever link made them.
    claims: Vec<(String, String)>,
    /// Interface indexes of the served users' additional-route links, sorted.
    own_links: Vec<u32>,
    /// Routes of the other links inside the tunnels' networks, as narrow as or
    /// narrower than the one they sit in: those addresses never take the tunnel.
    local_networks: Vec<Ipv4Network>,
}

impl Published {
    /// Rebuild the readers' view; returns whether it holds anything.
    fn refresh(&mut self) -> bool {
        let tunnels = self.tunnels.as_deref().unwrap_or_default();
        let mut namespaces: Vec<String> = self
            .claims
            .iter()
            .filter(|(adapter, _)| {
                tunnels
                    .iter()
                    .any(|(_, name)| name.eq_ignore_ascii_case(adapter))
            })
            .map(|(_, suffix)| suffix.clone())
            .collect();
        namespaces.sort_unstable();
        namespaces.dedup();
        namespaces.truncate(MAX_ENTRIES);
        let facts = ForeignTunnelFacts::new(&self.networks, namespaces);
        let any = !facts.is_empty();
        self.facts = Arc::new(facts);
        any
    }
}

/// Last-published facts. Empty means "none known", which every reader treats
/// as "no restriction".
#[derive(Default)]
pub struct ForeignTunnelCell {
    inner: RwLock<Published>,
    /// The facts hold something; read before the lock.
    any: AtomicBool,
}

impl ForeignTunnelCell {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn update(&self, change: impl FnOnce(&mut Published)) {
        let mut published = self.inner.write().unwrap_or_else(|p| p.into_inner());
        change(&mut published);
        let any = published.refresh();
        self.any.store(any, Ordering::Release);
    }

    /// Replace the foreign tunnels and their networks: `foreign` are the
    /// coordinator's foreign interface indexes, `routes` and `adapters` the
    /// same reading it named them from.
    pub fn publish_tunnels(
        &self,
        routes: &[RouteEntry],
        adapters: &[AdapterInfo],
        foreign: &[u32],
    ) {
        let mut networks = networks_of(routes, foreign);
        networks.truncate(MAX_ENTRIES);
        let local_networks = local_networks_inside(routes, foreign, &networks);
        let tunnels: Vec<(u32, String)> = foreign
            .iter()
            .map(|&index| {
                let name = adapters
                    .iter()
                    .find(|a| a.index == index)
                    .map(|a| a.adapter_name.clone())
                    .unwrap_or_default();
                (index, name)
            })
            .collect();
        let mut renamed = false;
        self.update(|p| {
            let names = |t: &[(u32, String)]| -> Vec<String> {
                let mut names: Vec<String> =
                    t.iter().map(|(_, n)| n.to_ascii_lowercase()).collect();
                names.sort_unstable();
                names
            };
            renamed = p.tunnels.as_deref().map(names) != Some(names(&tunnels));
            p.networks = networks;
            p.local_networks = local_networks;
            p.tunnels = Some(tunnels);
        });
        if renamed {
            // The namespace exemptions follow this set; let the guard re-read.
            crate::dns_stack::namespace_recheck().store(true, Ordering::SeqCst);
        }
    }

    /// Publish one pass over the served users: `per_user` holds each one's
    /// foreign tunnels, named from `table` and `adapters`, and a link counts
    /// only when it is foreign to all of them (another user's additional link
    /// is no tunnel of this one's, but it is not the corporate network
    /// either). `own` are the users' additional-route links.
    ///
    /// No table publishes no tunnels rather than leaving the last pass's
    /// facts standing: doubt is "not foreign".
    pub fn publish_served(
        &self,
        table: Option<&[RouteEntry]>,
        adapters: &[AdapterInfo],
        per_user: &[Vec<u32>],
        own: &[u32],
    ) {
        self.publish_own_links(own.to_vec());
        let Some(table) = table else {
            self.publish_tunnels(&[], &[], &[]);
            return;
        };
        let mut users = per_user.iter();
        let common: Vec<u32> = match users.next() {
            Some(first) => first
                .iter()
                .copied()
                .filter(|index| users.clone().all(|other| other.contains(index)))
                .collect(),
            None => Vec::new(),
        };
        self.publish_tunnels(table, adapters, &common);
    }

    /// Replace the served users' additional-route links. A link of ours is
    /// nobody else's tunnel, and its default says nothing about which link is
    /// the uplink: the namespace classifier leaves these out of both questions.
    pub fn publish_own_links(&self, mut links: Vec<u32>) {
        links.sort_unstable();
        links.dedup();
        links.truncate(MAX_ENTRIES);
        let mut changed = false;
        {
            let mut published = self.inner.write().unwrap_or_else(|p| p.into_inner());
            if published.own_links != links {
                published.own_links = links;
                changed = true;
            }
        }
        if changed {
            crate::dns_stack::namespace_recheck().store(true, Ordering::SeqCst);
        }
    }

    /// The served users' additional-route links, as last published.
    #[must_use]
    pub fn own_links(&self) -> Vec<u32> {
        let published = self.inner.read().unwrap_or_else(|p| p.into_inner());
        published.own_links.clone()
    }

    /// Did the coordinator name the adapter `adapter_id` a foreign tunnel?
    #[must_use]
    pub fn names_adapter(&self, adapter_id: &str) -> bool {
        let published = self.inner.read().unwrap_or_else(|p| p.into_inner());
        published.tunnels.as_deref().is_some_and(|tunnels| {
            tunnels
                .iter()
                .any(|(_, name)| !name.is_empty() && name.eq_ignore_ascii_case(adapter_id))
        })
    }

    /// Replace the networks foreign tunnels carry, leaving the tunnels as named.
    pub fn publish_networks(&self, mut networks: Vec<Ipv4Network>) {
        networks.sort_unstable();
        networks.dedup();
        networks.truncate(MAX_ENTRIES);
        self.update(|p| p.networks = networks);
    }

    /// Replace the namespace claims, as `(adapter name, suffix)`: suffixes
    /// lower-case with no dots at the ends. Only a claim by a link the
    /// coordinator named foreign is published to readers.
    pub fn publish_claims(&self, mut claims: Vec<(String, String)>) {
        claims.retain(|(_, suffix)| !suffix.is_empty());
        for (_, suffix) in &mut claims {
            suffix.make_ascii_lowercase();
        }
        claims.sort_unstable();
        claims.dedup();
        claims.truncate(MAX_ENTRIES);
        self.update(|p| p.claims = claims);
    }

    /// Namespaces with no link behind them, for tests of the readers.
    #[cfg(test)]
    pub(crate) fn claim_namespaces_for_tests(&self, namespaces: &[&str]) {
        const LINK: &str = "{test-tunnel}";
        self.update(|p| {
            p.tunnels
                .get_or_insert_with(Vec::new)
                .push((u32::MAX, LINK.to_owned()));
            p.claims = namespaces
                .iter()
                .map(|ns| (LINK.to_owned(), ns.to_ascii_lowercase()))
                .collect();
        });
    }

    /// One reading for every check of an answer; `None` when nothing is known.
    #[must_use]
    pub fn snapshot(&self) -> Option<Arc<ForeignTunnelFacts>> {
        if !self.any.load(Ordering::Acquire) {
            return None;
        }
        let published = self.inner.read().unwrap_or_else(|p| p.into_inner());
        Some(Arc::clone(&published.facts))
    }

    /// The coordinator's foreign interface indexes; `None` until it has named
    /// them.
    #[must_use]
    pub fn interfaces(&self) -> Option<Vec<u32>> {
        let published = self.inner.read().unwrap_or_else(|p| p.into_inner());
        published
            .tunnels
            .as_ref()
            .map(|tunnels| tunnels.iter().map(|(index, _)| *index).collect())
    }

    /// Does a foreign tunnel carry `ip`?
    #[must_use]
    pub fn carries(&self, ip: Ipv4Addr) -> bool {
        self.snapshot().is_some_and(|facts| facts.carries(ip))
    }

    /// Does a foreign tunnel carry any of `ips`?
    #[must_use]
    pub fn carries_any(&self, ips: &[Ipv4Addr]) -> bool {
        self.snapshot().is_some_and(|facts| facts.carries_any(ips))
    }

    /// Is `ip` reached through a foreign tunnel, by longest prefix? A home
    /// router on its own LAN inside a corporate `/16` is reached locally. A tie
    /// goes to the local link: doubt is "not foreign".
    #[must_use]
    pub fn routes_through_tunnel(&self, ip: Ipv4Addr) -> bool {
        if !self.carries(ip) {
            return false;
        }
        let published = self.inner.read().unwrap_or_else(|p| p.into_inner());
        let longest = |networks: &[Ipv4Network]| {
            networks
                .iter()
                .filter(|net| net.contains(ip))
                .map(|net| net.prefix_len())
                .max()
        };
        match (
            longest(&published.networks),
            longest(&published.local_networks),
        ) {
            (Some(tunnel), Some(local)) => tunnel > local,
            (Some(_), None) => true,
            (None, _) => false,
        }
    }

    /// Does a foreign tunnel's namespace hold `hostname`, on a label boundary?
    #[must_use]
    pub fn claims_name(&self, hostname: &str) -> bool {
        self.snapshot()
            .is_some_and(|facts| facts.claims_name(hostname))
    }
}

/// The process-wide cell.
pub fn global_foreign_tunnels() -> Arc<ForeignTunnelCell> {
    static CELL: OnceLock<Arc<ForeignTunnelCell>> = OnceLock::new();
    Arc::clone(CELL.get_or_init(|| Arc::new(ForeignTunnelCell::new())))
}

/// The IPv4 networks `routes` send over the interfaces in `foreign`, by the
/// same test the route planner keeps them direct by.
#[must_use]
pub fn networks_of(routes: &[RouteEntry], foreign: &[u32]) -> Vec<Ipv4Network> {
    crate::route_codegen::network_routes::foreign_tunnel_blocks(routes, foreign)
        .into_iter()
        .filter_map(|block| match block.network() {
            IpAddr::V4(net) => Ipv4Network::new(net, block.prefix_len()),
            IpAddr::V6(_) => None,
        })
        .collect()
}

/// Main-table IPv4 routes of links outside `foreign` that sit inside one of
/// `tunnel` and are at least as narrow; nothing else can win a lookup there.
fn local_networks_inside(
    routes: &[RouteEntry],
    foreign: &[u32],
    tunnel: &[Ipv4Network],
) -> Vec<Ipv4Network> {
    if tunnel.is_empty() {
        return Vec::new();
    }
    let mut local: Vec<Ipv4Network> = routes
        .iter()
        .filter(|r| {
            r.table == nrr_platform_api::RouteTableRef::Main
                && !foreign.contains(&r.interface_index)
        })
        .filter_map(|r| match r.destination {
            IpAddr::V4(destination) => Ipv4Network::new(destination, r.prefix_length),
            IpAddr::V6(_) => None,
        })
        .filter(|local| {
            tunnel
                .iter()
                .any(|t| t.prefix_len() <= local.prefix_len() && t.contains(local.network()))
        })
        .collect();
    local.sort_unstable();
    local.dedup();
    local.truncate(MAX_ENTRIES);
    local
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::adapters::{IfOperStatus, InterfaceType};

    fn net(text: &str) -> Ipv4Network {
        Ipv4Network::parse(text).expect("network")
    }

    fn route(dest: [u8; 4], prefix: u8, ifindex: u32, ours: bool) -> RouteEntry {
        RouteEntry {
            destination: IpAddr::V4(Ipv4Addr::from(dest)),
            prefix_length: prefix,
            next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            interface_index: ifindex,
            metric: 10,
            is_ours: ours,
            table: Default::default(),
        }
    }

    fn adapter(index: u32, name: &str) -> AdapterInfo {
        AdapterInfo {
            index,
            adapter_name: name.into(),
            description: name.into(),
            friendly_name: name.into(),
            mac: None,
            interface_type: InterfaceType::Tunnel,
            oper_status: IfOperStatus::Up,
            ipv4_addresses: Vec::new(),
            ipv6_addresses: Vec::new(),
            gateways: Vec::new(),
        }
    }

    #[test]
    fn an_unreadable_pass_keeps_the_users_links_and_names_no_tunnel() {
        let cell = ForeignTunnelCell::new();
        cell.publish_served(None, &[], &[vec![3, 4]], &[7, 5]);
        assert_eq!(cell.own_links(), vec![5, 7]);
        assert_eq!(cell.interfaces(), Some(Vec::new()));
    }

    #[test]
    fn a_tunnel_is_foreign_only_when_it_is_foreign_to_every_served_user() {
        let cell = ForeignTunnelCell::new();
        let adapters = [adapter(3, "corp"), adapter(4, "other")];
        cell.publish_served(Some(&[]), &adapters, &[vec![3, 4], vec![3]], &[]);
        assert_eq!(cell.interfaces(), Some(vec![3]));
    }

    #[test]
    fn an_empty_cell_restricts_nothing() {
        let cell = ForeignTunnelCell::new();
        assert!(cell.snapshot().is_none());
        assert!(!cell.carries(Ipv4Addr::new(192, 168, 78, 5)));
        assert!(!cell.claims_name("rdg.corp.example"));
        assert_eq!(cell.interfaces(), None);
    }

    #[test]
    fn a_tunnel_network_carries_its_addresses_and_nothing_beside_them() {
        let cell = ForeignTunnelCell::new();
        cell.publish_networks(vec![net("192.168.78.0/24")]);
        assert!(cell.carries(Ipv4Addr::new(192, 168, 78, 40)));
        assert!(cell.carries(Ipv4Addr::new(192, 168, 78, 0)));
        assert!(cell.carries(Ipv4Addr::new(192, 168, 78, 255)));
        assert!(cell.carries_any(&[
            Ipv4Addr::new(203, 0, 113, 1),
            Ipv4Addr::new(192, 168, 78, 1)
        ]));
        assert!(!cell.carries(Ipv4Addr::new(192, 168, 79, 1)));
        assert!(!cell.carries(Ipv4Addr::new(192, 168, 77, 255)));
        cell.publish_networks(Vec::new());
        assert!(!cell.carries(Ipv4Addr::new(192, 168, 78, 40)));
        assert!(cell.snapshot().is_none());
    }

    #[test]
    fn nested_and_neighbouring_networks_carry_exactly_their_union() {
        let cell = ForeignTunnelCell::new();
        cell.publish_networks(vec![
            net("10.0.0.0/8"),
            net("10.20.0.0/16"),
            net("172.20.0.0/24"),
            net("172.20.1.0/24"),
            net("198.51.100.7/32"),
            net("255.255.255.0/24"),
        ]);
        for inside in [
            [10, 0, 0, 0],
            [10, 255, 255, 255],
            [10, 20, 5, 5],
            [172, 20, 1, 200],
            [198, 51, 100, 7],
            [255, 255, 255, 255],
        ] {
            assert!(cell.carries(Ipv4Addr::from(inside)), "{inside:?}");
        }
        for outside in [
            [9, 255, 255, 255],
            [11, 0, 0, 0],
            [172, 20, 2, 0],
            [198, 51, 100, 6],
            [198, 51, 100, 8],
        ] {
            assert!(!cell.carries(Ipv4Addr::from(outside)), "{outside:?}");
        }
    }

    #[test]
    fn a_namespace_holds_its_names_on_a_label_boundary() {
        let cell = ForeignTunnelCell::new();
        cell.claim_namespaces_for_tests(&["corp.example", "Intra"]);
        assert!(cell.claims_name("corp.example"));
        assert!(cell.claims_name("RDG.Corp.Example."));
        assert!(cell.claims_name(" a.b.corp.example "));
        assert!(cell.claims_name("host.intra"));
        assert!(!cell.claims_name("notcorp.example"));
        assert!(!cell.claims_name("corp.example.org"));
        assert!(!cell.claims_name("example"));
        assert!(!cell.claims_name(""));
    }

    /// The user's own VPN pushing a search suffix is no corporate namespace:
    /// a claim counts only when the coordinator named its link foreign, and
    /// before it has named any, none does.
    #[test]
    fn only_a_link_the_coordinator_names_foreign_claims_a_namespace() {
        let cell = ForeignTunnelCell::new();
        cell.publish_claims(vec![
            ("{corp}".into(), "corp.example".into()),
            ("{mine}".into(), "vpn.example".into()),
        ]);
        assert!(!cell.claims_name("rdg.corp.example"), "nothing named yet");
        let adapters = [adapter(9, "{CORP}"), adapter(12, "{mine}")];
        cell.publish_tunnels(&[], &adapters, &[9]);
        assert!(cell.claims_name("rdg.corp.example"));
        assert!(!cell.claims_name("portal.vpn.example"));
        assert_eq!(cell.interfaces(), Some(vec![9]));
        cell.publish_tunnels(&[], &adapters, &[]);
        assert!(
            !cell.claims_name("rdg.corp.example"),
            "the tunnel went away"
        );
        assert_eq!(cell.interfaces(), Some(Vec::new()));
    }

    /// Our links are a fact for the namespace classifier, never a restriction
    /// on the answer path.
    #[test]
    fn our_links_restrict_no_reader() {
        let cell = ForeignTunnelCell::new();
        assert!(cell.own_links().is_empty());
        cell.publish_own_links(vec![12, 7, 12]);
        assert_eq!(cell.own_links(), vec![7, 12]);
        assert!(cell.snapshot().is_none());
        assert!(!cell.names_adapter("{mine}"));
    }

    #[test]
    fn only_the_tunnels_own_routes_are_its_networks() {
        let routes = [
            route([192, 168, 78, 0], 24, 7, false),
            route([0, 0, 0, 0], 0, 7, false),
            route([10, 9, 0, 0], 16, 7, true),
            route([172, 20, 0, 0], 16, 3, false),
        ];
        assert_eq!(networks_of(&routes, &[7]), vec![net("192.168.78.0/24")]);
    }

    /// An OpenVPN def1 pair (or a default route) is the tunnel taking all
    /// traffic, not a network of its own: counting it would make every IPv4
    /// address corporate.
    #[test]
    fn a_full_tunnels_catch_all_routes_are_no_network_of_its_own() {
        let routes = [
            route([0, 0, 0, 0], 1, 7, false),
            route([128, 0, 0, 0], 1, 7, false),
            route([0, 0, 0, 0], 0, 7, false),
            route([10, 0, 0, 0], 7, 7, false),
            route([224, 0, 0, 0], 4, 7, false),
            route([10, 30, 0, 0], 16, 7, false),
        ];
        assert_eq!(networks_of(&routes, &[7]), vec![net("10.30.0.0/16")]);
        let cell = ForeignTunnelCell::new();
        cell.publish_tunnels(&routes, &[adapter(7, "{corp}")], &[7]);
        assert!(!cell.carries(Ipv4Addr::new(203, 0, 113, 1)));
        assert!(cell.carries(Ipv4Addr::new(10, 30, 1, 1)));
    }
}
