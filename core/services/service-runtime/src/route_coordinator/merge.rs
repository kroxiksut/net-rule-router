//! Several users' routes in the one machine table.
//!
//! Each served user's plan is laid in longest-served first. A route nobody
//! contests goes in; one identical to a route already in (same destination,
//! same link) is shared; one that would take a destination from an earlier
//! user — the same network through another link, a narrower piece of their
//! rule network, or an overlay over theirs — stays out, and that user gets a
//! conflict instead. With their leak guard on, the later user's own filters
//! still pin the destination to their link: a route they lose is blocked for
//! them, not sent the other way.
//!
//! Pure: no I/O, so every rule here is tested without a route table.

use std::collections::HashMap;
use std::net::IpAddr;

use nrr_platform_api::RouteEntry;
use nrr_shared::ip_block::IpBlock;

use crate::route_codegen::is_overlay_route;

/// One destination a later user asked for and an earlier user holds.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RouteConflict {
    pub sid: String,
    pub holder: String,
    pub destination: IpAddr,
    pub prefix_length: u8,
}

/// What the table carries for all served users together.
#[derive(Debug, Default)]
pub(crate) struct MergedRoutes {
    /// The union to install, each route once.
    pub routes: Vec<RouteEntry>,
    /// Per user, the routes of theirs that went in (shared ones included).
    pub contributed: HashMap<String, Vec<RouteEntry>>,
    pub conflicts: Vec<RouteConflict>,
    pub view: MergedRouteView,
}

struct Accepted<'a> {
    route: &'a RouteEntry,
    owner: &'a str,
    block: Option<IpBlock>,
    overlay: bool,
}

fn block_of(route: &RouteEntry) -> Option<IpBlock> {
    IpBlock::new(route.destination, route.prefix_length)
}

/// Does `candidate` (a later user's) take traffic `held` (an earlier user's,
/// through another link) already carries?
fn takes_from(candidate: &RouteEntry, candidate_overlay: bool, held: &Accepted<'_>) -> bool {
    let (Some(c), Some(h)) = (block_of(candidate), held.block) else {
        return false;
    };
    match (candidate_overlay, held.overlay) {
        // A rule route beats an overlay by design: the overlay is "everything
        // the rules do not name", for the earlier user as much as anyone.
        (false, true) => false,
        // Two overlays through different links: whichever is narrower wins the
        // overlap, and the earlier user's default must not move.
        (true, true) => c.overlaps(h),
        // Inside the earlier user's rule route: the narrower one would win.
        (_, false) => h.covers(c),
    }
}

/// Lay `plans` (longest-served first) into one table.
pub(crate) fn merge_user_routes(plans: &[(String, Vec<RouteEntry>)]) -> MergedRoutes {
    let mut out = MergedRoutes::default();
    // Exact destinations, for the common case of host routes.
    let mut exact: HashMap<(IpAddr, u8), usize> = HashMap::new();
    // Rule networks and overlays: few, and the only shapes that can cover a
    // destination other than their own.
    let mut wide: Vec<usize> = Vec::new();
    let mut accepted: Vec<Accepted<'_>> = Vec::new();
    for (sid, routes) in plans {
        let mine = out.contributed.entry(sid.clone()).or_default();
        for route in routes {
            let overlay = is_overlay_route(route);
            let key = (route.destination, route.prefix_length);
            if let Some(&at) = exact.get(&key) {
                let held = &accepted[at];
                if held.route.interface_index == route.interface_index {
                    mine.push(route.clone());
                } else if held.owner != sid {
                    out.conflicts.push(RouteConflict {
                        sid: sid.clone(),
                        holder: held.owner.to_string(),
                        destination: route.destination,
                        prefix_length: route.prefix_length,
                    });
                }
                continue;
            }
            let taken_from = wide.iter().map(|&at| &accepted[at]).find(|held| {
                held.owner != sid
                    && held.route.interface_index != route.interface_index
                    && takes_from(route, overlay, held)
            });
            if let Some(held) = taken_from {
                out.conflicts.push(RouteConflict {
                    sid: sid.clone(),
                    holder: held.owner.to_string(),
                    destination: route.destination,
                    prefix_length: route.prefix_length,
                });
                continue;
            }
            let block = block_of(route);
            let index = accepted.len();
            if overlay || block.is_some_and(|b| !b.is_single_address()) {
                wide.push(index);
            }
            if let (false, Some(block)) = (overlay, block) {
                out.view.claim(block, sid, route.interface_index);
            }
            exact.insert(key, index);
            accepted.push(Accepted {
                route,
                owner: sid,
                block,
                overlay,
            });
            mine.push(route.clone());
            out.routes.push(route.clone());
        }
    }
    out
}

/// Which link the merged table sends a destination through, and on whose
/// behalf — what the service accounts' share of the guard has to agree with.
/// Overlays are left out: they are nobody's named destination.
#[derive(Debug, Default)]
pub(crate) struct MergedRouteView {
    hosts: HashMap<IpAddr, (String, u32)>,
    networks: Vec<(IpBlock, String, u32)>,
    /// Each served user's own additional link, as the merge saw it.
    links: HashMap<String, u32>,
}

impl MergedRouteView {
    /// The first claim on a destination is its owner's: plans are laid in
    /// longest-served first, and a later identical route only shares it.
    fn claim(&mut self, block: IpBlock, sid: &str, link: u32) {
        if block.is_single_address() {
            self.hosts
                .entry(block.network())
                .or_insert_with(|| (sid.to_string(), link));
        } else if !self.networks.iter().any(|(b, _, _)| *b == block) {
            self.networks.push((block, sid.to_string(), link));
        }
    }

    pub(crate) fn set_link(&mut self, sid: &str, link: Option<u32>) {
        match link {
            Some(link) => self.links.insert(sid.to_string(), link),
            None => self.links.remove(sid),
        };
    }

    /// Does the table send `block` through a link other than `sid`'s own for
    /// another user? `false` where nobody routes it, or `sid` itself does.
    pub(crate) fn claimed_elsewhere(&self, sid: &str, block: IpBlock) -> bool {
        let own_link = self.links.get(sid).copied();
        let foreign = |owner: &str, link: u32| owner != sid && Some(link) != own_link;
        if block.is_single_address() {
            if let Some((owner, link)) = self.hosts.get(&block.network()) {
                return foreign(owner.as_str(), *link);
            }
        }
        self.networks
            .iter()
            .filter(|(net, _, _)| net.covers(block))
            .max_by_key(|(net, _, _)| net.prefix_len())
            .is_some_and(|(_, owner, link)| foreign(owner.as_str(), *link))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const A: &str = "S-1-5-21-1-2-3-1001";
    const B: &str = "S-1-5-21-1-2-3-1002";

    fn route(dest: [u8; 4], prefix: u8, ifindex: u32, metric: u32) -> RouteEntry {
        RouteEntry {
            destination: IpAddr::V4(Ipv4Addr::from(dest)),
            prefix_length: prefix,
            next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, ifindex as u8)),
            interface_index: ifindex,
            metric,
            is_ours: true,
            table: nrr_platform_api::RouteTableRef::Main,
        }
    }

    fn host(d: u8, ifindex: u32) -> RouteEntry {
        route(
            [198, 51, 100, d],
            32,
            ifindex,
            crate::route_codegen::SECONDARY_ROUTE_METRIC,
        )
    }

    fn overlay(first: u8, ifindex: u32) -> RouteEntry {
        route(
            [first, 0, 0, 0],
            1,
            ifindex,
            crate::route_codegen::SECONDARY_ROUTE_METRIC,
        )
    }

    fn plans(a: Vec<RouteEntry>, b: Vec<RouteEntry>) -> Vec<(String, Vec<RouteEntry>)> {
        vec![(A.to_string(), a), (B.to_string(), b)]
    }

    fn block(text: &str) -> IpBlock {
        IpBlock::parse(text).unwrap()
    }

    #[test]
    fn disjoint_plans_are_both_installed() {
        let merged = merge_user_routes(&plans(vec![host(1, 9)], vec![host(2, 11)]));
        assert_eq!(merged.routes, vec![host(1, 9), host(2, 11)]);
        assert!(merged.conflicts.is_empty());
    }

    #[test]
    fn one_destination_through_one_link_is_shared() {
        let merged = merge_user_routes(&plans(vec![host(1, 9)], vec![host(1, 9)]));
        assert_eq!(merged.routes, vec![host(1, 9)]);
        assert!(merged.conflicts.is_empty());
        assert_eq!(merged.contributed[B], vec![host(1, 9)]);
    }

    #[test]
    fn the_earlier_user_keeps_a_destination_wanted_through_another_link() {
        let merged = merge_user_routes(&plans(vec![host(1, 9)], vec![host(1, 11), host(2, 11)]));
        assert_eq!(merged.routes, vec![host(1, 9), host(2, 11)]);
        assert_eq!(merged.conflicts.len(), 1);
        assert_eq!(merged.conflicts[0].sid, B);
        assert_eq!(merged.conflicts[0].holder, A);
        assert_eq!(merged.contributed[B], vec![host(2, 11)]);
    }

    #[test]
    fn a_narrower_piece_of_an_earlier_users_network_stays_out() {
        let network = route(
            [198, 51, 100, 0],
            24,
            9,
            crate::route_codegen::NETWORK_ROUTE_METRIC,
        );
        let merged = merge_user_routes(&plans(vec![network.clone()], vec![host(7, 11)]));
        assert_eq!(merged.routes, vec![network]);
        assert_eq!(merged.conflicts.len(), 1);
    }

    #[test]
    fn a_wider_network_around_an_earlier_users_host_goes_in() {
        // The earlier user's narrower host route still wins for its address.
        let network = route(
            [198, 51, 100, 0],
            24,
            11,
            crate::route_codegen::NETWORK_ROUTE_METRIC,
        );
        let merged = merge_user_routes(&plans(vec![host(1, 9)], vec![network.clone()]));
        assert_eq!(merged.routes, vec![host(1, 9), network]);
        assert!(merged.conflicts.is_empty());
    }

    #[test]
    fn a_later_users_overlay_never_moves_an_earlier_users_default() {
        // Earlier: mode B through its tunnel. Later: a counter-overlay through
        // the main link, one bit longer — it would win the whole half.
        let counter = route(
            [0, 0, 0, 0],
            2,
            3,
            crate::route_codegen::SECONDARY_ROUTE_METRIC,
        );
        let merged = merge_user_routes(&plans(
            vec![overlay(0, 9), overlay(128, 9)],
            vec![counter, host(2, 11)],
        ));
        assert_eq!(
            merged.routes,
            vec![overlay(0, 9), overlay(128, 9), host(2, 11)]
        );
        assert_eq!(merged.conflicts.len(), 1);
    }

    #[test]
    fn a_later_users_rule_route_inside_an_earlier_users_overlay_goes_in() {
        let merged = merge_user_routes(&plans(vec![overlay(128, 9)], vec![host(2, 11)]));
        assert_eq!(merged.routes, vec![overlay(128, 9), host(2, 11)]);
        assert!(merged.conflicts.is_empty());
    }

    #[test]
    fn the_view_names_what_another_users_link_carries() {
        let network = route(
            [203, 0, 113, 0],
            24,
            9,
            crate::route_codegen::NETWORK_ROUTE_METRIC,
        );
        let mut merged = merge_user_routes(&plans(
            vec![host(1, 9), network, overlay(0, 9)],
            vec![host(1, 11), host(2, 11)],
        ));
        merged.view.set_link(A, Some(9));
        merged.view.set_link(B, Some(11));
        let view = &merged.view;
        assert!(!view.claimed_elsewhere(A, block("198.51.100.1/32")));
        assert!(view.claimed_elsewhere(B, block("198.51.100.1/32")));
        assert!(!view.claimed_elsewhere(B, block("198.51.100.2/32")));
        assert!(view.claimed_elsewhere(B, block("203.0.113.5/32")));
        assert!(view.claimed_elsewhere(B, block("203.0.113.0/25")));
        // Overlays are nobody's named destination.
        assert!(!view.claimed_elsewhere(B, block("1.2.3.4/32")));
    }
}
