//! The neutral plan over held networks, judged by the precedence order every
//! lowering realises rather than by its shape.

use std::net::IpAddr;

use nrr_platform_api::enforcement::{
    Coverage, DstMatch, EgressConstraint, EgressRef, FlowRule, L4Proto, PrecedenceClass, Verdict,
};
use nrr_shared::ip_block::IpBlock;

use crate::enforcement_planner::{
    plan_fail_closed_destinations, plan_fail_closed_networks, plan_kill_switch_destinations,
    plan_kill_switch_networks, NetworkHoldInput, NetworkHolds, NETWORK_ORDINAL_BASE,
};
use crate::killswitch_codegen::KillSwitchProtocols;

const SID: &str = "S-1-5-21-1000-1000-1000-1001";

fn net(text: &str) -> IpBlock {
    IpBlock::parse(text).expect("block")
}

fn addr(text: &str) -> IpAddr {
    text.parse().expect("address")
}

/// Additional `10.20.0.0/16` and `2001:db8::/48` (held), `10.30.0.0/15` (too
/// wide); main `10.20.5.0/24`, `2001:db8:0:5::/64` and named `10.20.9.9`;
/// pinned `10.20.5.200` inside the main /24; tunnel server `10.20.100.1`,
/// a LAN `10.20.200.0/24`.
fn scenario() -> (NetworkHolds, Vec<IpAddr>) {
    let additional = [
        net("10.20.0.0/16"),
        net("10.30.0.0/15"),
        net("2001:db8::/48"),
    ];
    let main = [net("10.20.5.0/24"), net("2001:db8:0:5::/64")];
    let main_addresses = [addr("10.20.9.9")];
    let pinned = vec![addr("10.20.5.200")];
    let never_block = [net("10.20.100.1/32"), net("10.20.200.0/24")];
    let holds = NetworkHolds::compute(&NetworkHoldInput {
        additional_networks: &additional,
        main_networks: &main,
        main_addresses: &main_addresses,
        pinned: &pinned,
        never_block: &never_block,
    });
    (holds, pinned)
}

fn dst_contains(dst: DstMatch, ip: IpAddr) -> bool {
    let block = match dst {
        DstMatch::Any => return true,
        DstMatch::HostV4(h) => return ip == IpAddr::V4(h),
        DstMatch::HostV6(h) => return ip == IpAddr::V6(h),
        DstMatch::SubnetV4 { net, prefix } => IpBlock::new(IpAddr::V4(net), prefix),
        DstMatch::SubnetV6 { net, prefix } => IpBlock::new(IpAddr::V6(net), prefix),
    };
    block.is_some_and(|b| b.contains(ip))
}

/// The verdict of the highest-precedence flow that matches, or `None` when the
/// plan says nothing about the packet (it follows the routes).
fn verdict(flows: &[FlowRule], ip: &str, via_tunnel: bool, proto: L4Proto) -> Option<Verdict> {
    let ip = addr(ip);
    let connect = matches!(proto, L4Proto::Tcp | L4Proto::Udp);
    let mut best: Option<&FlowRule> = None;
    for flow in flows {
        let covered = match flow.coverage {
            Coverage::ConnectOnly => connect,
            Coverage::AllPackets => !connect,
        };
        if !covered
            || !dst_contains(flow.flow.dst, ip)
            || flow.flow.protocol.is_some_and(|p| p != proto)
        {
            continue;
        }
        if best.is_none_or(|b| flow.precedence.is_higher_priority_than(b.precedence)) {
            best = Some(flow);
        }
    }
    best.map(|flow| match flow.egress {
        EgressConstraint::OnlyVia(EgressRef::Secondary) if !via_tunnel => Verdict::Block,
        _ => flow.verdict,
    })
}

fn fail_closed_plan() -> Vec<FlowRule> {
    let (holds, pinned) = scenario();
    let mut flows = plan_fail_closed_destinations(SID, &pinned, KillSwitchProtocols::ALL);
    flows.extend(plan_fail_closed_networks(
        SID,
        &holds,
        KillSwitchProtocols::ALL,
    ));
    flows
}

#[test]
fn with_the_tunnel_gone_a_held_network_is_blocked_and_a_wide_one_is_not() {
    let flows = fail_closed_plan();
    for proto in [L4Proto::Tcp, L4Proto::Icmp] {
        assert_eq!(
            verdict(&flows, "10.20.1.1", false, proto),
            Some(Verdict::Block),
            "{proto:?}"
        );
        assert_eq!(
            verdict(&flows, "10.30.1.1", false, proto),
            None,
            "{proto:?}"
        );
    }
    assert_eq!(
        verdict(&flows, "2001:db8:0:1::1", false, L4Proto::Tcp),
        Some(Verdict::Block)
    );
}

#[test]
fn with_the_tunnel_gone_the_narrower_main_rule_still_wins() {
    let flows = fail_closed_plan();
    for proto in [L4Proto::Tcp, L4Proto::Udp, L4Proto::Icmp] {
        for ip in ["10.20.5.7", "10.20.9.9"] {
            assert_eq!(
                verdict(&flows, ip, false, proto),
                Some(Verdict::Permit),
                "{ip} {proto:?}"
            );
        }
        // The pinned address inside the main /24 is the narrower rule again.
        assert_eq!(
            verdict(&flows, "10.20.5.200", false, proto),
            Some(Verdict::Block),
            "{proto:?}"
        );
    }
    assert_eq!(
        verdict(&flows, "2001:db8:0:5::1", false, L4Proto::Tcp),
        Some(Verdict::Permit)
    );
}

#[test]
fn a_held_network_never_blocks_the_tunnel_server_or_a_lan() {
    let flows = fail_closed_plan();
    for proto in [L4Proto::Tcp, L4Proto::Icmp] {
        for ip in ["10.20.100.1", "10.20.200.50"] {
            assert_eq!(
                verdict(&flows, ip, false, proto),
                Some(Verdict::Permit),
                "{ip} {proto:?}"
            );
        }
    }
}

#[test]
fn with_the_tunnel_up_the_pin_permits_through_it_and_blocks_around_it() {
    let (holds, pinned) = scenario();
    let mut flows = plan_kill_switch_destinations(SID, &pinned, KillSwitchProtocols::ALL);
    flows.extend(plan_kill_switch_networks(
        SID,
        &holds,
        KillSwitchProtocols::ALL,
    ));
    for proto in [L4Proto::Tcp, L4Proto::Icmp] {
        assert_eq!(
            verdict(&flows, "10.20.1.1", true, proto),
            Some(Verdict::Permit)
        );
        assert_eq!(
            verdict(&flows, "10.20.1.1", false, proto),
            Some(Verdict::Block)
        );
        assert_eq!(
            verdict(&flows, "10.20.5.7", false, proto),
            Some(Verdict::Permit)
        );
        assert_eq!(
            verdict(&flows, "10.20.5.200", false, proto),
            Some(Verdict::Block)
        );
    }
    assert_eq!(
        verdict(&flows, "2001:db8:0:1::1", false, L4Proto::Tcp),
        Some(Verdict::Block)
    );
}

#[test]
fn one_flow_per_held_block_and_per_cut_out_never_per_address() {
    let (holds, _) = scenario();
    let tcp_udp = KillSwitchProtocols::from_bits(0x03);
    let flows = plan_fail_closed_networks(SID, &holds, tcp_udp);
    assert_eq!(flows.len(), holds.held.len() + holds.cut_outs.len());
    let blocks = flows
        .iter()
        .filter(|f| f.precedence.class == PrecedenceClass::KillSwitchBlock)
        .count();
    assert_eq!(blocks, holds.held.len());
}

#[test]
fn network_ordinals_start_past_every_pin() {
    let (holds, _) = scenario();
    let flows = plan_kill_switch_networks(SID, &holds, KillSwitchProtocols::ALL);
    assert!(!flows.is_empty());
    assert!(flows
        .iter()
        .all(|f| f.precedence.ordinal >= NETWORK_ORDINAL_BASE));
}

#[test]
fn an_icmp_only_mask_plans_no_connect_layer_flow() {
    let (holds, _) = scenario();
    let icmp = KillSwitchProtocols::from_bits(0x04);
    for flows in [
        plan_fail_closed_networks(SID, &holds, icmp),
        plan_kill_switch_networks(SID, &holds, icmp),
    ] {
        assert!(!flows.is_empty());
        assert!(flows.iter().all(|f| f.coverage == Coverage::AllPackets));
    }
    assert!(plan_fail_closed_networks(SID, &holds, KillSwitchProtocols::from_bits(0)).is_empty());
}
