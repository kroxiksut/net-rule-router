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
    let out = forwarded_guard_filters(OWNER, &guard(ServiceAccountPosture::Pin), TUNNEL_LUID, &[]);
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
    assert!(forwarded_guard_filters(OWNER, &guard(ServiceAccountPosture::Pin), 0, &[]).is_empty());
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
        dns_servers: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))],
        ..FailClosedExemptions::default()
    };
    let dns = [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 54))];
    let out = forwarded_block_all_filters(OWNER, &exemptions, &dns, &[]);
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

/// Every forwarded packet is judged against the blanket, so the hosts it keeps
/// open cost a handful of filters, not one each, and every one stays open.
#[test]
fn the_forwarded_blanket_keeps_many_direct_hosts_open_in_few_filters() {
    let direct: Vec<Ipv4Addr> = (0..2000u32)
        .map(|n| Ipv4Addr::from(0xC633_6400u32 + n))
        .collect();
    let exemptions = FailClosedExemptions {
        known_direct_ips: direct.clone(),
        ..FailClosedExemptions::default()
    };
    let out = forwarded_block_all_filters(OWNER, &exemptions, &[], &[]);
    assert!(out.len() < 100, "{} filters", out.len());
    let block_all = out
        .iter()
        .find(|f| {
            f.action == WfpAction::Block
                && f.layer == WfpLayerKey::IpForwardV4
                && !f.names_a_destination()
        })
        .expect("a blanket block");
    for ip in direct {
        assert!(
            out.iter().any(|f| f.action == WfpAction::Permit
                && f.weight > block_all.weight
                && f.covers_v4(ip)),
            "{ip} stays open"
        );
    }
}

#[test]
fn a_block_closes_every_guarded_destination_on_the_forwarding_path() {
    let out = forwarded_guard_filters(OWNER, &guard(ServiceAccountPosture::Block), 0, &[]);
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
    let forwarded = forwarded_guard_filters(OWNER, &g, 0, &[]);
    let service = service_account_filters(OWNER, &g, 0, KillSwitchProtocols::ALL, &[], &[]);
    assert!(!forwarded.is_empty() && !service.is_empty());
    let mut ids: Vec<u64> = forwarded.iter().chain(&service).map(|f| f.id.raw).collect();
    let total = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), total);
}

const CORP_LUID: u64 = 0x00AB_CDEF_0000_0009;

fn corp() -> Vec<ForeignTunnelNetwork> {
    vec![ForeignTunnelNetwork {
        luid: CORP_LUID,
        network: IpBlock::parse("10.77.0.0/16").expect("net"),
    }]
}

/// A service reaches the corporate network through the corporate tunnel while
/// ours is guarded, as the owner does; only that network, never everything.
#[test]
fn service_accounts_and_forwarded_traffic_keep_the_corporate_networks() {
    for posture in [ServiceAccountPosture::Pin, ServiceAccountPosture::Block] {
        let luid = if posture == ServiceAccountPosture::Pin {
            TUNNEL_LUID
        } else {
            0
        };
        let service = service_account_filters(
            OWNER,
            &guard(posture),
            luid,
            KillSwitchProtocols::ALL,
            &[],
            &corp(),
        );
        let forwarded = forwarded_guard_filters(OWNER, &guard(posture), luid, &corp());
        for (name, set) in [("service", &service), ("forwarded", &forwarded)] {
            let permits: Vec<_> = set
                .iter()
                .filter(|f| f.local_interface_luid == Some(CORP_LUID))
                .collect();
            assert!(
                !permits.is_empty(),
                "{posture:?} {name}: no corporate permit"
            );
            for f in &permits {
                assert_eq!(f.action, WfpAction::Permit, "{posture:?} {name}");
                assert_eq!(
                    f.remote_subnet,
                    Some((Ipv4Addr::new(10, 77, 0, 0), 16)),
                    "{posture:?} {name}: narrowed to the network, never any destination"
                );
            }
        }
        assert!(service
            .iter()
            .filter(|f| f.local_interface_luid == Some(CORP_LUID))
            .all(|f| f.user_sid.as_deref()
                == Some(nrr_platform_api::types::SERVICE_ACCOUNTS_PRINCIPAL)));
        assert!(forwarded
            .iter()
            .filter(|f| f.local_interface_luid == Some(CORP_LUID))
            .all(|f| f.layer.is_forwarding() && f.user_sid.is_none()));
    }
}

/// Forwarded traffic, like the owner's, gets only a corporate tunnel's own
/// networks, never the tunnel whole.
#[test]
fn the_forwarded_blanket_spares_only_the_corporate_networks() {
    let exemptions = FailClosedExemptions {
        bootstrap_server_ips: vec![Ipv4Addr::new(192, 0, 2, 10)],
        foreign_tunnel_luids: vec![CORP_LUID],
        foreign_tunnel_networks: corp(),
        ..FailClosedExemptions::default()
    };
    let out = forwarded_block_all_filters(OWNER, &exemptions, &[], &[]);
    let corp_filters: Vec<_> = out
        .iter()
        .filter(|f| f.local_interface_luid == Some(CORP_LUID))
        .collect();
    assert!(!corp_filters.is_empty());
    assert!(corp_filters
        .iter()
        .all(|f| f.remote_subnet == Some((Ipv4Addr::new(10, 77, 0, 0), 16))));
}

/// Under the owner's blanket a guest still reaches the networks the main
/// link's rules route, in both families, while a tunnel-bound address inside
/// one stays held by the forwarded guard.
#[test]
fn the_forwarded_blanket_keeps_main_link_networks_open() {
    let exemptions = FailClosedExemptions {
        bootstrap_server_ips: vec![Ipv4Addr::new(192, 0, 2, 10)],
        ..FailClosedExemptions::default()
    };
    let networks = [
        IpBlock::parse("203.0.113.0/24").expect("net"),
        IpBlock::parse("198.18.0.0/15").expect("net"),
        IpBlock::parse("2001:db8:1::/48").expect("net"),
    ];
    let mut out = forwarded_block_all_filters(OWNER, &exemptions, &[], &networks);
    for f in &out {
        assert!(f.layer.is_forwarding(), "{f:?}");
        f.validate_layer_conditions()
            .expect("expressible at the forwarding layer");
    }
    out.extend(forwarded_guard_filters(
        OWNER,
        &guard(ServiceAccountPosture::Block),
        0,
        &[],
    ));
    let covers = |f: &WfpFilterSpec, ip: IpAddr| match ip {
        IpAddr::V4(v4) => {
            f.covers_v4(v4)
                || f.remote_subnet
                    .and_then(|(net, len)| IpBlock::new(IpAddr::V4(net), len))
                    .is_some_and(|b| b.contains(ip))
        }
        IpAddr::V6(v6) => {
            f.covers_v6(v6)
                || f.remote_subnet_v6
                    .and_then(|(net, len)| IpBlock::new(IpAddr::V6(net), len))
                    .is_some_and(|b| b.contains(ip))
        }
    };
    // The highest weight on the address's layer decides, as WFP does.
    let verdict = |ip: IpAddr| {
        let layer = if ip.is_ipv4() {
            WfpLayerKey::IpForwardV4
        } else {
            WfpLayerKey::IpForwardV6
        };
        out.iter()
            .filter(|f| f.layer == layer && (!f.names_a_destination() || covers(f, ip)))
            .max_by_key(|f| f.weight)
            .map(|f| f.action)
    };
    for ip in [
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)),
        IpAddr::V4(Ipv4Addr::new(198, 19, 7, 7)),
        IpAddr::V6("2001:db8:1::77".parse().expect("v6")),
    ] {
        assert_eq!(verdict(ip), Some(WfpAction::Permit), "{ip} stays open");
    }
    for ip in [
        // The guard's tunnel-bound address inside the /24.
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 80)),
        IpAddr::V6("2001:db8:2::1".parse().expect("v6")),
    ] {
        assert_eq!(verdict(ip), Some(WfpAction::Block), "{ip} stays held");
    }
    let mut ids: Vec<u64> = out.iter().map(|f| f.id.raw).collect();
    let total = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), total, "one id per filter");
}

const GUEST_LUID: u64 = 0x0006_0000_0000_001F;

/// The highest weight on `layer` among the filters matching a packet forwarded
/// out of `egress` to `dst` decides, as WFP does.
fn forwarded_verdict(
    out: &[WfpFilterSpec],
    layer: WfpLayerKey,
    dst: IpAddr,
    egress: u64,
) -> Option<WfpAction> {
    out.iter()
        .filter(|f| f.layer == layer)
        .filter(|f| f.local_interface_luid.is_none_or(|luid| luid == egress))
        .filter(|f| {
            !f.names_a_destination()
                || match dst {
                    IpAddr::V4(v4) => {
                        f.covers_v4(v4)
                            || f.remote_subnet
                                .and_then(|(net, len)| IpBlock::new(IpAddr::V4(net), len))
                                .is_some_and(|b| b.contains(dst))
                    }
                    IpAddr::V6(v6) => f.covers_v6(v6),
                }
        })
        .max_by_key(|f| f.weight)
        .map(|f| f.action)
}

/// The user refused the WSL network, so it is no local subnet; replies
/// forwarded into the guest still pass, while what the guest sends out to an
/// unknown address stays held.
#[test]
fn a_refused_guest_network_still_gets_its_replies_under_the_forwarded_blanket() {
    const UPLINK_LUID: u64 = 0x0006_0000_0000_000C;
    let exemptions = FailClosedExemptions {
        bootstrap_server_ips: vec![Ipv4Addr::new(192, 0, 2, 10)],
        local_subnets: vec![(Ipv4Addr::new(192, 168, 50, 0), 24)],
        guest_network_luids: vec![GUEST_LUID],
        ..FailClosedExemptions::default()
    };
    let out = forwarded_block_all_filters(OWNER, &exemptions, &[], &[]);
    for f in &out {
        f.validate_layer_conditions()
            .expect("expressible at the forwarding layer");
    }
    let guest = IpAddr::V4(Ipv4Addr::new(172, 23, 210, 5));
    let guest_v6: IpAddr = "fd00:23::5".parse().expect("v6");
    let internet = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99));
    assert_eq!(
        forwarded_verdict(&out, WfpLayerKey::IpForwardV4, guest, GUEST_LUID),
        Some(WfpAction::Permit),
        "a reply into the guest passes"
    );
    assert_eq!(
        forwarded_verdict(&out, WfpLayerKey::IpForwardV6, guest_v6, GUEST_LUID),
        Some(WfpAction::Permit),
        "in both families"
    );
    assert_eq!(
        forwarded_verdict(&out, WfpLayerKey::IpForwardV4, internet, UPLINK_LUID),
        Some(WfpAction::Block),
        "the guest's own traffic out stays held"
    );
    let without = FailClosedExemptions {
        guest_network_luids: Vec::new(),
        ..exemptions.clone()
    };
    let before = forwarded_block_all_filters(OWNER, &without, &[], &[]);
    assert_eq!(
        forwarded_verdict(&before, WfpLayerKey::IpForwardV4, guest, GUEST_LUID),
        Some(WfpAction::Block),
        "the fixture reproduces the dropped reply"
    );
    assert_eq!(out.len(), before.len() + 2, "one permit per family");
    let mut ids: Vec<u64> = out.iter().map(|f| f.id.raw).collect();
    let total = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), total, "one id per filter");
}

/// The guest permit lives only on the forwarding layers, which never see what
/// the machine itself sends: the owner's own blanket is the same with or
/// without guest networks, and no filter keyed on a guest is anywhere else.
#[test]
fn a_guest_permit_is_never_a_way_out_for_the_computers_own_traffic() {
    let with = FailClosedExemptions {
        bootstrap_server_ips: vec![Ipv4Addr::new(192, 0, 2, 10)],
        guest_network_luids: vec![GUEST_LUID],
        ..FailClosedExemptions::default()
    };
    let without = FailClosedExemptions {
        guest_network_luids: Vec::new(),
        ..with.clone()
    };
    assert_eq!(
        fail_closed_block_all_filters(OWNER, &with, KillSwitchProtocols::ALL),
        fail_closed_block_all_filters(OWNER, &without, KillSwitchProtocols::ALL),
    );
    let keyed: Vec<_> = forwarded_block_all_filters(OWNER, &with, &[], &[])
        .into_iter()
        .filter(|f| f.local_interface_luid == Some(GUEST_LUID))
        .collect();
    assert!(!keyed.is_empty());
    for f in &keyed {
        assert!(f.layer.is_forwarding(), "{f:?}");
        assert_eq!(f.action, WfpAction::Permit);
        assert_eq!(
            (f.user_sid.as_deref(), f.app_pattern.as_deref()),
            (None, None)
        );
    }
}

/// The tunnel and a foreign tunnel are never opened whole as a guest network,
/// and the count stays bounded however many adapters are named.
#[test]
fn the_guest_permits_skip_tunnels_and_stay_bounded() {
    let base = FailClosedExemptions {
        bootstrap_server_ips: vec![Ipv4Addr::new(192, 0, 2, 10)],
        secondary_luid: TUNNEL_LUID,
        foreign_tunnel_luids: vec![CORP_LUID],
        foreign_tunnel_networks: corp(),
        ..FailClosedExemptions::default()
    };
    let tunnels = FailClosedExemptions {
        guest_network_luids: vec![0, TUNNEL_LUID, CORP_LUID],
        ..base.clone()
    };
    assert_eq!(
        forwarded_block_all_filters(OWNER, &tunnels, &[], &[]),
        forwarded_block_all_filters(OWNER, &base, &[], &[]),
    );
    let many = FailClosedExemptions {
        guest_network_luids: (1..=40u64).map(|n| GUEST_LUID + n).collect(),
        ..base.clone()
    };
    let added = forwarded_block_all_filters(OWNER, &many, &[], &[]).len()
        - forwarded_block_all_filters(OWNER, &base, &[], &[]).len();
    assert_eq!(added, 2 * GUEST_NETWORK_MAX);
}
