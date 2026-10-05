use super::*;

use crate::enforcement_planner::{NetworkHoldInput, NetworkHolds};
use crate::wfp_bands::{band_of_filter, BASE_PRIMARY};
use nrr_shared::ip_block::IpBlock;

const SID: &str = "S-1-5-21-1000-1000-1000-1001";
const PRIMARY_LUID: u64 = 0x0001_0000_0000_0003;

fn net(text: &str) -> IpBlock {
    IpBlock::parse(text).expect("block")
}

fn addr(text: &str) -> IpAddr {
    text.parse().expect("address")
}

/// Additional `10.20.0.0/16` and `2001:db8::/48` (held), `10.30.0.0/15` (too
/// wide); main `10.20.5.0/24`, `2001:db8:0:5::/64` and named `10.20.9.9`;
/// pinned `10.20.5.200` inside the main /24; tunnel server `10.20.100.1` and a
/// LAN `10.20.200.0/24`, both inside the held /16.
fn exemptions() -> FailClosedExemptions {
    FailClosedExemptions {
        bootstrap_server_ips: vec![Ipv4Addr::new(10, 20, 100, 1)],
        local_subnets: vec![(Ipv4Addr::new(10, 20, 200, 0), 24)],
        ..FailClosedExemptions::default()
    }
}

fn scenario() -> (NetworkHolds, Vec<IpAddr>) {
    let additional = [
        net("10.20.0.0/16"),
        net("10.30.0.0/15"),
        net("2001:db8::/48"),
    ];
    let main = [net("10.20.5.0/24"), net("2001:db8:0:5::/64")];
    let main_addresses = [addr("10.20.9.9")];
    let pinned = vec![addr("10.20.5.200")];
    let never_block = exemptions().never_blocked_networks();
    let holds = NetworkHolds::compute(&NetworkHoldInput {
        additional_networks: &additional,
        main_networks: &main,
        main_addresses: &main_addresses,
        pinned: &pinned,
        never_block: &never_block,
    });
    (holds, pinned)
}

/// What the rule codegen puts beneath the kill switch for this user: the main
/// address's own permit and a main-link application's address-less permit.
fn rule_band() -> Vec<WfpFilterSpec> {
    let permit = |weight, remote_ip, app_pattern: Option<&str>, tag| WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Permit,
        remote_ip,
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight,
        id: filter_id_for(SID, "primary", "r1", "test", tag),
        user_sid: Some(SID.to_string()),
        app_pattern: app_pattern.map(str::to_string),
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    };
    vec![
        permit(
            BASE_PRIMARY,
            Some(Ipv4Addr::new(10, 20, 9, 9)),
            None,
            "named",
        ),
        permit(BASE_PRIMARY + 1, None, Some("main.exe"), "app"),
    ]
}

struct Packet {
    ip: IpAddr,
    luid: u64,
    proto: u8,
}

fn layer_of(p: &Packet) -> WfpLayerKey {
    match (p.ip, p.proto) {
        (IpAddr::V4(_), PROTO_TCP | PROTO_UDP) => WfpLayerKey::AleAuthConnectV4,
        (IpAddr::V4(_), _) => WfpLayerKey::OutboundTransportV4,
        (IpAddr::V6(_), _) => WfpLayerKey::AleAuthConnectV6,
    }
}

fn matches(f: &WfpFilterSpec, p: &Packet) -> bool {
    let in_block = |net: IpAddr, len: u8| IpBlock::new(net, len).is_some_and(|b| b.contains(p.ip));
    let remote = match (f.remote_ip, f.remote_subnet, f.remote_subnet_v6) {
        (Some(ip), _, _) => p.ip == IpAddr::V4(ip),
        (None, Some((net, len)), _) => in_block(IpAddr::V4(net), len),
        (None, None, Some((net, len))) => in_block(IpAddr::V6(net), len),
        (None, None, None) if !f.remote_ip_set.is_empty() || !f.remote_ip_set_v6.is_empty() => {
            f.remote_ip_set.iter().any(|ip| p.ip == IpAddr::V4(*ip))
                || f.remote_ip_set_v6.iter().any(|ip| p.ip == IpAddr::V6(*ip))
        }
        (None, None, None) => true,
    };
    f.layer == layer_of(p)
        && remote
        && f.user_sid.as_deref().is_none_or(|s| s == SID)
        && f.local_interface_luid.is_none_or(|l| l == p.luid)
        && f.ip_protocol.is_none_or(|proto| proto == p.proto)
        && f.remote_port.is_none()
        // The packet comes from an unlisted process.
        && f.app_pattern.is_none()
}

/// The action of the highest-weight matching filter; `None` lets it through.
fn verdict(filters: &[WfpFilterSpec], ip: &str, luid: u64, proto: u8) -> Option<WfpAction> {
    let p = Packet {
        ip: addr(ip),
        luid,
        proto,
    };
    filters
        .iter()
        .filter(|f| matches(f, &p))
        .max_by_key(|f| f.weight)
        .map(|f| f.action)
}

fn passes(filters: &[WfpFilterSpec], ip: &str, luid: u64, proto: u8) -> bool {
    verdict(filters, ip, luid, proto) != Some(WfpAction::Block)
}

fn fail_closed_set() -> Vec<WfpFilterSpec> {
    let (holds, pinned) = scenario();
    let mut filters = rule_band();
    filters.extend(fail_closed_block_destinations(
        SID,
        &pinned,
        KillSwitchProtocols::ALL,
    ));
    filters.extend(fail_closed_network_filters(
        SID,
        &holds,
        KillSwitchProtocols::ALL,
    ));
    filters
}

fn kill_switch_set() -> Vec<WfpFilterSpec> {
    let (holds, pinned) = scenario();
    let mut filters = rule_band();
    filters.extend(kill_switch_filters(
        SID,
        &pinned,
        LUID,
        KillSwitchProtocols::ALL,
    ));
    filters.extend(kill_switch_network_filters(
        SID,
        &holds,
        LUID,
        KillSwitchProtocols::ALL,
    ));
    filters
}

#[test]
fn with_the_tunnel_gone_a_slash_16_is_blocked_and_a_slash_15_is_not() {
    let filters = fail_closed_set();
    for proto in [PROTO_TCP, PROTO_UDP, PROTO_ICMP] {
        assert!(
            !passes(&filters, "10.20.1.1", PRIMARY_LUID, proto),
            "{proto}"
        );
        assert!(
            passes(&filters, "10.30.1.1", PRIMARY_LUID, proto),
            "{proto}"
        );
    }
    assert!(!passes(
        &filters,
        "2001:db8:0:1::1",
        PRIMARY_LUID,
        PROTO_TCP
    ));
}

#[test]
fn the_hold_outranks_a_main_link_applications_permit() {
    // An address rule beats an application rule: the main-link app must not
    // reach the additional link's network over the main link.
    let filters = fail_closed_set();
    let app_permit = &rule_band()[1];
    let hold = filters
        .iter()
        .find(|f| {
            f.action == WfpAction::Block
                && f.remote_subnet == Some((Ipv4Addr::new(10, 20, 0, 0), 16))
        })
        .expect("hold block");
    assert!(hold.weight > app_permit.weight);
}

#[test]
fn with_the_tunnel_gone_the_narrower_main_rule_still_wins() {
    let filters = fail_closed_set();
    for proto in [PROTO_TCP, PROTO_UDP, PROTO_ICMP] {
        assert!(
            passes(&filters, "10.20.5.7", PRIMARY_LUID, proto),
            "main /24 {proto}"
        );
        assert!(
            passes(&filters, "10.20.9.9", PRIMARY_LUID, proto),
            "main name {proto}"
        );
        assert!(
            !passes(&filters, "10.20.5.200", PRIMARY_LUID, proto),
            "the pin inside the main /24 is narrower again {proto}"
        );
    }
    assert!(passes(&filters, "2001:db8:0:5::1", PRIMARY_LUID, PROTO_TCP));
}

#[test]
fn a_held_network_never_blocks_the_tunnel_server_or_a_lan() {
    for filters in [fail_closed_set(), kill_switch_set()] {
        for proto in [PROTO_TCP, PROTO_UDP, PROTO_ICMP] {
            assert!(
                passes(&filters, "10.20.100.1", PRIMARY_LUID, proto),
                "{proto}"
            );
            assert!(
                passes(&filters, "10.20.200.9", PRIMARY_LUID, proto),
                "{proto}"
            );
        }
    }
}

#[test]
fn with_the_tunnel_up_a_held_network_passes_only_through_it() {
    let filters = kill_switch_set();
    for proto in [PROTO_TCP, PROTO_ICMP] {
        assert!(passes(&filters, "10.20.1.1", LUID, proto), "{proto}");
        assert!(
            !passes(&filters, "10.20.1.1", PRIMARY_LUID, proto),
            "{proto}"
        );
        assert!(
            passes(&filters, "10.20.5.7", PRIMARY_LUID, proto),
            "{proto}"
        );
        assert!(
            passes(&filters, "10.20.9.9", PRIMARY_LUID, proto),
            "{proto}"
        );
        assert!(
            !passes(&filters, "10.20.5.200", PRIMARY_LUID, proto),
            "{proto}"
        );
        assert!(passes(&filters, "10.20.5.200", LUID, proto), "{proto}");
        assert!(
            passes(&filters, "10.30.1.1", PRIMARY_LUID, proto),
            "{proto}"
        );
    }
    assert!(passes(&filters, "2001:db8:0:1::1", LUID, PROTO_TCP));
    assert!(!passes(
        &filters,
        "2001:db8:0:1::1",
        PRIMARY_LUID,
        PROTO_TCP
    ));
    assert!(passes(&filters, "2001:db8:0:5::1", PRIMARY_LUID, PROTO_TCP));
}

#[test]
fn filters_are_per_held_block_and_per_cut_out_never_per_address() {
    let (holds, _) = scenario();
    let named = KillSwitchProtocols::ALL.packet_named().len();
    let v4_holds = holds.held.iter().filter(|b| b.is_ipv4()).count();
    let v4_cuts = holds.cut_outs.iter().filter(|b| b.is_ipv4()).count();

    let fc = fail_closed_network_filters(SID, &holds, KillSwitchProtocols::ALL);
    assert_eq!(
        fc.len(),
        holds.held.len() + v4_holds * named + holds.cut_outs.len() + v4_cuts
    );
    let ks = kill_switch_network_filters(SID, &holds, LUID, KillSwitchProtocols::ALL);
    assert_eq!(
        ks.len(),
        2 * holds.held.len() + 2 * v4_holds * named + holds.cut_outs.len() + v4_cuts
    );
    let mut ids: Vec<_> = fc.iter().chain(&ks).map(|f| f.id).collect();
    let before = ids.len();
    ids.sort_unstable_by_key(|id| id.raw);
    ids.dedup();
    // The transport blocks and the cut-outs are shared by both postures on
    // purpose: a tunnel drop swaps only the filters that differ.
    assert_eq!(
        before - ids.len(),
        v4_holds * named + holds.cut_outs.len() + v4_cuts
    );
}

#[test]
fn network_filters_sit_in_their_bands_above_the_rule_permits() {
    let (holds, _) = scenario();
    for f in kill_switch_network_filters(SID, &holds, LUID, KillSwitchProtocols::ALL) {
        let band = band_of_filter(&f);
        if f.layer != WfpLayerKey::OutboundTransportV4 {
            let expected = match (f.action, f.local_interface_luid) {
                (WfpAction::Block, _) => "KILLSWITCH_NETWORK_BLOCK_BASE",
                (WfpAction::Permit, Some(_)) => "KILLSWITCH_NETWORK_PERMIT_BASE",
                _ => "NETWORK_CUT_OUT_BASE",
            };
            assert_eq!(band, expected, "{f:?}");
            assert!(f.weight > RULE_PRIMARY_BAND + 0x000F_FFFF);
            assert_eq!(f.user_sid.as_deref(), Some(SID));
        } else {
            assert_eq!(f.user_sid, None, "no user id below ALE");
        }
    }
}

#[test]
fn a_zero_luid_or_an_empty_mask_arms_nothing() {
    let (holds, _) = scenario();
    assert!(kill_switch_network_filters(SID, &holds, 0, KillSwitchProtocols::ALL).is_empty());
    assert!(fail_closed_network_filters(SID, &holds, KillSwitchProtocols::from_bits(0)).is_empty());
    assert!(
        fail_closed_network_filters(SID, &NetworkHolds::default(), KillSwitchProtocols::ALL)
            .is_empty()
    );
}

#[test]
fn the_permit_id_follows_the_tunnel_and_the_block_id_does_not() {
    let (holds, _) = scenario();
    let a = kill_switch_network_filters(SID, &holds, LUID, KillSwitchProtocols::ALL);
    let b = kill_switch_network_filters(SID, &holds, LUID + 1, KillSwitchProtocols::ALL);
    for (x, y) in a.iter().zip(&b) {
        if x.local_interface_luid.is_some() {
            assert_ne!(x.id, y.id);
        } else {
            assert_eq!(x.id, y.id);
        }
    }
}
