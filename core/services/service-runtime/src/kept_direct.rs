//! The segments a host route into the tunnel is withheld inside, published for
//! the explain probe, which is built at the other end of boot from the pass
//! that reads the machine.
//!
//! Kept per user: a tunnel one user bound is foreign to nobody else's view of
//! their own links, so one user's pass must not overwrite another's.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};

use crate::route_codegen::network_routes::{KeptDirect, NetworkRouteFacts};
use nrr_shared::ip_block::IpBlock;

#[derive(Default, Clone)]
struct Published {
    local: Vec<IpBlock>,
    foreign: Vec<IpBlock>,
}

/// Every user's last published segments.
#[derive(Default)]
struct PerUser(BTreeMap<String, Published>);

impl PerUser {
    fn publish(&mut self, sid: &str, facts: &NetworkRouteFacts) {
        let (local, foreign) = facts.kept_direct_blocks();
        self.0.insert(sid.to_owned(), Published { local, foreign });
    }

    fn facts(&self, sid: &str) -> NetworkRouteFacts {
        let published = self.0.get(sid).cloned().unwrap_or_default();
        NetworkRouteFacts {
            lan_segments: published.local,
            foreign_tunnel_routes: published.foreign,
            ..NetworkRouteFacts::default()
        }
    }

    fn reason(&self, sid: &str, ip: IpAddr) -> Option<KeptDirect> {
        let published = self.0.get(sid)?;
        if published.local.iter().any(|b| b.contains(ip)) {
            Some(KeptDirect::LocalNetwork)
        } else if published.foreign.iter().any(|b| b.contains(ip)) {
            Some(KeptDirect::ForeignTunnel)
        } else {
            None
        }
    }
}

fn cell() -> &'static Mutex<PerUser> {
    static CELL: OnceLock<Mutex<PerUser>> = OnceLock::new();
    CELL.get_or_init(Mutex::default)
}

fn lock() -> std::sync::MutexGuard<'static, PerUser> {
    cell().lock().unwrap_or_else(|p| p.into_inner())
}

/// Replace `sid`'s published view; one lock per pass.
pub fn publish(sid: &str, facts: &NetworkRouteFacts) {
    lock().publish(sid, facts);
}

/// Drop what `sid` published: a pass that could not read the machine names
/// nothing, since doubt is "not foreign".
pub fn forget(sid: &str) {
    lock().0.remove(sid);
}

/// Keep only the users in `served`.
pub fn retain_only(served: &[String]) {
    lock().0.retain(|sid, _| served.contains(sid));
}

/// Drop every user's view.
pub fn forget_all() {
    lock().0.clear();
}

/// `sid`'s last published segments as facts, for a path that must not read the
/// machine (a DNS answer introducing an address).
pub fn published_facts(sid: &str) -> NetworkRouteFacts {
    lock().facts(sid)
}

/// Why `ip` is kept out of `sid`'s tunnel, by the last published reading.
pub fn reason(sid: &str, ip: IpAddr) -> Option<KeptDirect> {
    lock().reason(sid, ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn facts(foreign: &str) -> NetworkRouteFacts {
        NetworkRouteFacts {
            foreign_tunnel_routes: vec![IpBlock::new(
                IpAddr::V4(foreign.parse::<Ipv4Addr>().expect("ip")),
                24,
            )
            .expect("block")],
            ..NetworkRouteFacts::default()
        }
    }

    #[test]
    fn one_users_pass_does_not_overwrite_anothers() {
        let mut users = PerUser::default();
        users.publish("a", &facts("198.51.100.0"));
        users.publish("b", &facts("203.0.113.0"));
        let in_a = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
        let in_b = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        assert_eq!(users.reason("a", in_a), Some(KeptDirect::ForeignTunnel));
        assert_eq!(users.reason("a", in_b), None);
        assert_eq!(users.reason("b", in_b), Some(KeptDirect::ForeignTunnel));
        assert_eq!(users.reason("b", in_a), None);
        assert!(!users.facts("a").foreign_tunnel_routes.is_empty());
        assert!(users.facts("nobody").foreign_tunnel_routes.is_empty());
        users.0.remove("a");
        assert_eq!(users.reason("a", in_a), None);
        assert_eq!(users.reason("b", in_b), Some(KeptDirect::ForeignTunnel));
    }
}
