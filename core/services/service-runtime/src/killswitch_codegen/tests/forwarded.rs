use super::*;

use crate::enforcement_planner::{NetworkHolds, ServiceAccountGuard, ServiceAccountPosture};
use nrr_shared::ip_block::IpBlock;

const OWNER: &str = "S-1-5-21-1000-1000-1000-1001";

fn guard(posture: ServiceAccountPosture) -> ServiceAccountGuard {
    ServiceAccountGuard {
        posture,
        destinations: vec![
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            IpAddr::V6("2001:db8::5".parse().expect("v6")),
        ],
        holds: NetworkHolds {
            held: vec![IpBlock::parse("198.51.100.0/24").expect("net")],
            cut_outs: vec![IpBlock::parse("198.51.100.1/32").expect("net")],
            ..NetworkHolds::default()
        },
        dns_spared: Vec::new(),
    }
}

const TUNNEL_LUID: u64 = 0x0001_0000_0000_0007;

/// A pin is the owner's pair keyed on the egress: permitted only out the
/// tunnel, blocked the instant the route table sends it anywhere else.
#[test]
fn a_pin_holds_forwarded_traffic_to_the_tunnel() {
    let out = forwarded_guard_filters(OWNER, &guard(ServiceAccountPosture::Pin), TUNNEL_LUID);
    for f in &out {
        assert!(f.layer.is_forwarding(), "{f:?}");
        assert_eq!(
            (f.user_sid.as_deref(), f.ip_protocol, f.remote_port),
            (None, None, None)
        );
        f.validate_layer_conditions()
            .expect("expressible at the forwarding layer");
    }
    for covers in [
        &(|f: &WfpFilterSpec| f.covers_v4(Ipv4Addr::new(203, 0, 113, 5)))
            as &dyn Fn(&WfpFilterSpec) -> bool,
        &|f: &WfpFilterSpec| f.covers_v6("2001:db8::5".parse().expect("v6")),
        &|f: &WfpFilterSpec| f.remote_subnet == Some((Ipv4Addr::new(198, 51, 100, 0), 24)),
    ] {
        let permit = out
            .iter()
            .find(|f| f.action == WfpAction::Permit && covers(f))
            .expect("a permit out the tunnel");
        assert_eq!(permit.local_interface_luid, Some(TUNNEL_LUID));
        let block = out
            .iter()
            .find(|f| f.action == WfpAction::Block && covers(f))
            .expect("a block everywhere else");
        assert_eq!(block.local_interface_luid, None);
        assert!(permit.weight > block.weight, "the pin outranks its block");
    }
}

/// Without the tunnel's LUID a pin could never match: it fails open, like the
/// owner's.
#[test]
fn a_pin_without_the_tunnel_fails_open() {
    assert!(forwarded_guard_filters(OWNER, &guard(ServiceAccountPosture::Pin), 0).is_empty());
}

/// Under the owner's blanket, forwarded traffic is held whole, save the floor,
/// the direct hosts and the main link's resolvers.
#[test]
fn the_owners_blanket_holds_forwarded_traffic_whole() {
    let exemptions = FailClosedExemptions {
        bootstrap_server_ips: vec![Ipv4Addr::new(192, 0, 2, 10)],
        local_subnets: vec![(Ipv4Addr::new(192, 168, 50, 0), 24)],
        primary_dest_ips: vec![Ipv4Addr::new(198, 51, 100, 20)],
        allow_dns_over_primary: true,
        dns_servers: vec![Ipv4Addr::new(192, 0, 2, 53)],
        ..FailClosedExemptions::default()
    };
    let dns = [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 54))];
    let out = forwarded_block_all_filters(OWNER, &exemptions, &dns);
    for f in &out {
        assert!(f.layer.is_forwarding(), "{f:?}");
        assert_eq!(
            (f.user_sid.as_deref(), f.ip_protocol, f.remote_port),
            (None, None, None)
        );
        f.validate_layer_conditions()
            .expect("expressible at the forwarding layer");
    }
    let block_all = out
        .iter()
        .find(|f| {
            f.action == WfpAction::Block
                && f.layer == WfpLayerKey::IpForwardV4
                && f.remote_ip.is_none()
                && f.remote_ip_set.is_empty()
                && f.remote_subnet.is_none()
        })
        .expect("a blanket block");
    let open = |pred: &dyn Fn(&WfpFilterSpec) -> bool| {
        out.iter()
            .any(|f| f.action == WfpAction::Permit && f.weight > block_all.weight && pred(f))
    };
    for ip in [
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(198, 51, 100, 20),
        Ipv4Addr::new(192, 0, 2, 54),
    ] {
        assert!(open(&|f| f.covers_v4(ip)), "{ip} stays open");
    }
    assert!(open(
        &|f| f.remote_subnet == Some((Ipv4Addr::new(192, 168, 50, 0), 24))
    ));
    let mut ids: Vec<u64> = out.iter().map(|f| f.id.raw).collect();
    let total = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), total, "one id per filter");
}

#[test]
fn a_block_closes_every_guarded_destination_on_the_forwarding_path() {
    let out = forwarded_guard_filters(OWNER, &guard(ServiceAccountPosture::Block), 0);
    for f in &out {
        assert!(f.layer.is_forwarding(), "{f:?}");
        assert_eq!(f.user_sid, None);
        assert_eq!(f.ip_protocol, None);
        assert_eq!(f.app_pattern, None);
        f.validate_layer_conditions()
            .expect("expressible at the forwarding layer");
    }
    let blocks = |pred: &dyn Fn(&WfpFilterSpec) -> bool| {
        out.iter().any(|f| f.action == WfpAction::Block && pred(f))
    };
    assert!(blocks(
        &|f| f.layer == WfpLayerKey::IpForwardV4 && f.covers_v4(Ipv4Addr::new(203, 0, 113, 5))
    ));
    assert!(blocks(
        &|f| f.layer == WfpLayerKey::IpForwardV6 && f.covers_v6("2001:db8::5".parse().expect("v6"))
    ));
    assert!(blocks(
        &|f| f.remote_subnet == Some((Ipv4Addr::new(198, 51, 100, 0), 24))
    ));
    let cut = out
        .iter()
        .find(|f| f.action == WfpAction::Permit)
        .expect("the cut-out stays open");
    assert_eq!(cut.remote_ip, Some(Ipv4Addr::new(198, 51, 100, 1)));
    let hold = out
        .iter()
        .find(|f| f.remote_subnet.is_some())
        .expect("the hold");
    assert!(cut.weight > hold.weight, "a cut-out outranks its hold");
}

/// The forwarded set is its own: an owner's service-account twins and these
/// never claim one id.
#[test]
fn the_forwarded_set_shares_no_id_with_the_service_accounts() {
    let g = guard(ServiceAccountPosture::Block);
    let forwarded = forwarded_guard_filters(OWNER, &g, 0);
    let service = service_account_filters(OWNER, &g, 0, KillSwitchProtocols::ALL, &[]);
    assert!(!forwarded.is_empty() && !service.is_empty());
    let mut ids: Vec<u64> = forwarded.iter().chain(&service).map(|f| f.id.raw).collect();
    let total = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), total);
}
