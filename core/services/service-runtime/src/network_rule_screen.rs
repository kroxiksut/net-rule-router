//! The service's own screen for a submitted network rule: the part of its
//! validation that depends on what this machine looks like right now.

use std::net::IpAddr;
use std::sync::Arc;

use nrr_domain::ip_network_policy::canonical_block;
use nrr_platform_api::fake_ip::FakeIpPoolConfig;
use nrr_platform_api::route_table::RouteTablePort;
use nrr_shared::ip_block::IpBlock;

use crate::fake_ip::network_overlaps_fake_ip_pool;
use crate::production_mutation_executor::{NetworkRuleConflict, NetworkRuleScreen};
use crate::route_codegen::network_routes::{network_conflicts_with_links, NetworkRouteFacts};

/// Reads the link facts for one principal's submission.
pub type LinkFactsFn = Arc<dyn Fn(&str) -> NetworkRouteFacts + Send + Sync>;

/// Facts from the OS route table and adapters alone. The tunnel's index and
/// servers are not known without a route coordinator, so only attached
/// networks are protected. An unreadable table answers with no facts: a
/// submission is not the place to fail on a transient read.
#[must_use]
pub fn facts_from_route_table(port: &dyn RouteTablePort) -> NetworkRouteFacts {
    facts_with_servers(port, Vec::new())
}

/// [`facts_from_route_table`] plus the tunnel servers the planner remembered,
/// so a network over a server is refused while its tunnel is down. The store
/// is read once per submission and holds whatever the last pass saw live.
#[must_use]
pub fn facts_with_remembered_servers(
    port: Arc<dyn RouteTablePort>,
    remembered: crate::route_coordinator::ServerIpLoaderFn,
) -> LinkFactsFn {
    Arc::new(move |_| {
        let servers = remembered().into_iter().map(IpAddr::V4).collect();
        facts_with_servers(port.as_ref(), servers)
    })
}

fn facts_with_servers(port: &dyn RouteTablePort, servers: Vec<IpAddr>) -> NetworkRouteFacts {
    let (Ok(routes), Ok(adapters)) = (port.get_ip_forward_table(), port.get_adapter_infos()) else {
        return NetworkRouteFacts::default();
    };
    NetworkRouteFacts::read(&routes, &adapters, None, servers)
}

/// The first conflict `network` has with the machine, the pool first.
#[must_use]
pub fn screen_network(
    network: IpBlock,
    facts: &NetworkRouteFacts,
    pool: Option<&FakeIpPoolConfig>,
) -> Option<NetworkRuleConflict> {
    if pool.is_some_and(|pool| network_overlaps_fake_ip_pool(network, pool)) {
        return Some(NetworkRuleConflict::CoversFakeIpPool);
    }
    network_conflicts_with_links(canonical_block(network), facts)
        .map(NetworkRuleConflict::CoversLink)
}

/// Screens against live link facts and, where the platform has one, the
/// fake-IP pool.
pub struct ProductionNetworkScreen {
    facts: LinkFactsFn,
    pool: Option<FakeIpPoolConfig>,
}

impl ProductionNetworkScreen {
    #[must_use]
    pub fn new(facts: LinkFactsFn, pool: Option<FakeIpPoolConfig>) -> Self {
        Self { facts, pool }
    }
}

impl NetworkRuleScreen for ProductionNetworkScreen {
    fn checker(
        &self,
        principal: &str,
    ) -> Box<dyn Fn(IpBlock) -> Option<NetworkRuleConflict> + Send> {
        // One reading per submission, however many networks it adds.
        let facts = (self.facts)(principal);
        let pool = self.pool;
        Box::new(move |network| screen_network(network, &facts, pool.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    fn net(text: &str) -> IpBlock {
        IpBlock::parse(text).expect("block")
    }

    fn facts() -> NetworkRouteFacts {
        NetworkRouteFacts {
            local_networks: vec![net("192.168.1.0/24")],
            tunnel_servers: vec!["203.0.113.7".parse::<IpAddr>().expect("ip")],
            ..NetworkRouteFacts::default()
        }
    }

    #[test]
    fn a_network_over_the_tunnel_server_or_a_lan_is_a_link_conflict() {
        let pool = FakeIpPoolConfig::default();
        for text in ["203.0.113.0/24", "192.168.0.0/16", "192.168.1.0/24"] {
            assert!(
                matches!(
                    screen_network(net(text), &facts(), Some(&pool)),
                    Some(NetworkRuleConflict::CoversLink(_))
                ),
                "{text}"
            );
        }
    }

    #[test]
    fn a_network_inside_a_connected_lan_is_refused_too() {
        // Routed off the LAN's own link it would take part of the LAN away.
        assert!(matches!(
            screen_network(net("192.168.1.128/25"), &facts(), None),
            Some(NetworkRuleConflict::CoversLink(_))
        ));
    }

    #[test]
    fn a_disjoint_network_passes() {
        let pool = FakeIpPoolConfig::default();
        assert_eq!(
            screen_network(net("198.51.100.0/24"), &facts(), Some(&pool)),
            None
        );
    }

    #[test]
    fn a_network_over_the_pool_is_a_pool_conflict_and_no_pool_is_no_conflict() {
        let pool = FakeIpPoolConfig::default();
        assert_eq!(
            screen_network(net("198.18.0.0/16"), &facts(), Some(&pool)),
            Some(NetworkRuleConflict::CoversFakeIpPool)
        );
        assert_eq!(
            screen_network(net("198.18.0.0/16"), &facts(), None),
            None,
            "a platform without a pool has nothing to overlap"
        );
    }

    #[test]
    fn the_checker_reads_the_facts_once_per_submission() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let reads = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&reads);
        let screen = ProductionNetworkScreen::new(
            Arc::new(move |_| {
                counted.fetch_add(1, Ordering::SeqCst);
                facts()
            }),
            None,
        );
        let check = screen.checker("principal");
        assert!(check(net("192.168.0.0/16")).is_some());
        assert!(check(net("198.51.100.0/24")).is_none());
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }
}
