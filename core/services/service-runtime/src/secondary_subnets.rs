//! The additional route's own subnets, published once and read from anywhere.
//!
//! Two parts of the service need this fact and are built at opposite ends of
//! boot: the route coordinator learns it on every reconcile, and the fake-IP
//! answerer — constructed long before the coordinator exists — must consult it
//! on every answer. A process cell decouples the two, exactly like the other
//! live values the boot order will not let us thread directly.
//!
//! Why the fact matters: addresses inside the tunnel's own subnet are reachable
//! only from inside the tunnel. Handing out a virtual address for one of them
//! points the caller at our TUN, where nothing speaks the tunnel's protocol —
//! observed live as a VPN client failing to authorize against `10.117.0.1` on a
//! `10.88.0.0/10` link.

use std::sync::{Arc, Mutex, OnceLock};

use nrr_domain::ipv4_network::Ipv4Network;

/// Last-published set. Empty means "not known yet", which every reader treats
/// as "no restriction" — the behaviour before this existed.
#[derive(Default)]
pub struct SecondarySubnetsCell {
    inner: Mutex<Vec<Ipv4Network>>,
}

impl SecondarySubnetsCell {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the set. Called from the reconcile, which is the only place that
    /// enumerates adapters — publishing costs one lock per cycle.
    pub fn publish(&self, subnets: Vec<Ipv4Network>) {
        *self.inner.lock().unwrap_or_else(|p| p.into_inner()) = subnets;
    }

    pub fn current(&self) -> Vec<Ipv4Network> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

/// The process-wide cell. Same rationale as `dns_egress::global_dns_via_secondary`:
/// one fact, two owners that cannot be introduced to each other at boot.
pub fn global_secondary_subnets() -> Arc<SecondarySubnetsCell> {
    static CELL: OnceLock<Arc<SecondarySubnetsCell>> = OnceLock::new();
    Arc::clone(CELL.get_or_init(|| Arc::new(SecondarySubnetsCell::new())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unpublished_cell_restricts_nothing() {
        assert!(SecondarySubnetsCell::new().current().is_empty());
    }

    #[test]
    fn publishing_replaces_rather_than_accumulates() {
        let cell = SecondarySubnetsCell::new();
        cell.publish(vec![Ipv4Network::parse("10.88.0.0/10").expect("parse")]);
        cell.publish(vec![Ipv4Network::parse("10.7.0.0/24").expect("parse")]);
        assert_eq!(
            cell.current(),
            vec![Ipv4Network::parse("10.7.0.0/24").expect("parse")],
            "the tunnel moved; the old subnet must not linger"
        );
    }
}
