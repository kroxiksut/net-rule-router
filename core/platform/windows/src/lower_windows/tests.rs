use super::*;
use nrr_platform_api::enforcement::{
    AppScope, Coverage, EgressConstraint, FlowMatch, Precedence, PrincipalScope, UserPrincipal,
};
use nrr_platform_api::wfp_behavioral::behaviorally_equivalent;
use std::net::Ipv4Addr;

fn route_flow(role: RouteRole, ordinal: u32, ip: Ipv4Addr) -> FlowRule {
    FlowRule {
        verdict: Verdict::Permit,
        precedence: Precedence {
            class: PrecedenceClass::RouteRule(role),
            ordinal,
        },
        flow: FlowMatch {
            dst: DstMatch::HostV4(ip),
            dst_port: None,
            protocol: None,
        },
        principal: PrincipalScope(UserPrincipal::from_windows_sid("S-1-5-21-A").ok()),
        app: AppScope::Any,
        egress: EgressConstraint::Any,
        coverage: Coverage::ConnectOnly,
    }
}

fn plan(flows: Vec<FlowRule>) -> EnforcementPlan {
    EnforcementPlan {
        principal: UserPrincipal::from_windows_sid("S-1-5-21-A").unwrap_or(UserPrincipal::Baseline),
        flows,
        routes: Vec::new(),
        policy_rules: Vec::new(),
    }
}

fn block_flow(ordinal: u32, ip: Ipv4Addr) -> FlowRule {
    FlowRule {
        verdict: Verdict::Block,
        precedence: Precedence {
            class: PrecedenceClass::HardBlock,
            ordinal,
        },
        flow: FlowMatch {
            dst: DstMatch::HostV4(ip),
            dst_port: None,
            protocol: None,
        },
        principal: PrincipalScope(UserPrincipal::from_windows_sid("S-1-5-21-A").ok()),
        app: AppScope::Any,
        egress: EgressConstraint::Any,
        coverage: Coverage::AllPackets,
    }
}

#[test]
fn lowers_exact_ip_permit_with_expected_fields() {
    let p = plan(vec![route_flow(
        RouteRole::Primary,
        0,
        Ipv4Addr::new(203, 0, 113, 5),
    )]);
    let out = lower_route_rules(&p);
    assert_eq!(out.len(), 1);
    let f = &out[0];
    assert_eq!(f.layer, WfpLayerKey::AleAuthConnectV4);
    assert_eq!(f.action, WfpAction::Permit);
    // Packed: the address rides in the set, and `covers_v4` is the
    // question every consumer actually asks.
    assert!(f.covers_v4(Ipv4Addr::new(203, 0, 113, 5)));
    assert_eq!(f.user_sid.as_deref(), Some("S-1-5-21-A"));
    assert_eq!(f.weight, BASE_PRIMARY);
    assert!(f.app_pattern.is_none() && f.local_interface_luid.is_none());
}

#[test]
fn primary_outranks_secondary_and_ids_are_deterministic() {
    let p = plan(vec![
        route_flow(RouteRole::Primary, 0, Ipv4Addr::new(198, 51, 100, 1)),
        route_flow(RouteRole::Secondary, 0, Ipv4Addr::new(198, 51, 100, 2)),
    ]);
    let a = lower_route_rules(&p);
    let b = lower_route_rules(&p);
    assert_eq!(a, b, "same plan → identical filters (re-apply = no churn)");
    assert!(behaviorally_equivalent(&a, &b));
    // Primary weight band is above secondary.
    assert!(a[0].weight > a[1].weight);
}

#[test]
fn block_emits_ale_plus_packet_mirror_with_distinct_ids() {
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    let out = lower_route_rules(&plan(vec![block_flow(0, ip)]));
    assert_eq!(out.len(), 2, "block → ALE filter + packet-layer mirror");
    let ale = &out[0];
    let pkt = &out[1];
    assert_eq!(ale.layer, WfpLayerKey::AleAuthConnectV4);
    assert_eq!(ale.action, WfpAction::Block);
    assert_eq!(ale.user_sid.as_deref(), Some("S-1-5-21-A"));
    assert_eq!(pkt.layer, WfpLayerKey::OutboundIpPacketV4);
    assert_eq!(pkt.action, WfpAction::Block);
    assert!(
        pkt.user_sid.is_none(),
        "packet layer carries no ALE user id"
    );
    assert_eq!(ale.weight, pkt.weight, "mirror shares the ALE weight");
    assert_ne!(ale.id, pkt.id, "the pair must have distinct filter ids");
    assert_eq!(ale.weight, BASE_BLOCK);
}
/// Two exemptions that differ only by the conditions they carry must get
/// DIFFERENT ids.
///
/// Seeded on `(sid, layer, action, weight)` alone they collided, the second
/// add came back `FWP_E_ALREADY_EXISTS` — which the batch counts as success
/// — and the result was a phantom: recorded installed, absent from WFP,
/// enforcing nothing. The behavioural oracle cannot see this, because it
/// ignores ids by construction.
#[test]
fn catch_all_ids_separate_filters_that_differ_only_in_their_conditions() {
    let sid = Some("S-1-5-21-1-2-3-1001");
    let base = |disc: &str| {
        derive_catch_all_id(
            sid,
            WfpLayerKey::AleAuthConnectV4,
            WfpAction::Permit,
            100,
            disc,
        )
    };
    assert_ne!(base("198.51.100.1|53"), base("198.51.100.8|53"));
    assert_ne!(base("198.51.100.1|53"), base("198.51.100.1|443"));
    // Same inputs still give the same id — the whole point of deriving it.
    assert_eq!(base("198.51.100.1|53"), base("198.51.100.1|53"));
}

/// Fail-closed ALE groups for two protocols over the same addresses share a
/// weight by the codegen's formula; only the id keeps the second group from
/// being swallowed as `FWP_E_ALREADY_EXISTS`.
#[test]
fn fail_closed_ale_groups_per_protocol_get_distinct_ids() {
    use nrr_platform_api::enforcement::L4Proto;
    let fail_closed = |ordinal: u32, protocol: L4Proto| FlowRule {
        verdict: Verdict::Block,
        precedence: Precedence {
            class: PrecedenceClass::KillSwitchBlock,
            ordinal,
        },
        flow: FlowMatch {
            dst: DstMatch::HostV4(Ipv4Addr::new(203, 0, 113, 7)),
            dst_port: None,
            protocol: Some(protocol),
        },
        principal: PrincipalScope(UserPrincipal::from_windows_sid("S-1-5-21-A").ok()),
        app: AppScope::Any,
        egress: EgressConstraint::Any,
        coverage: Coverage::ConnectOnly,
    };
    let out = lower_kill_switch(
        &plan(vec![
            fail_closed(0, L4Proto::Tcp),
            fail_closed(1, L4Proto::Udp),
        ]),
        7,
    );
    assert_eq!(out.len(), 2, "one ALE block per protocol group");
    assert_eq!(out[0].weight, out[1].weight);
    assert_ne!(out[0].ip_protocol, out[1].ip_protocol);
    assert_ne!(out[0].id, out[1].id);
}

fn network_flow(class: PrecedenceClass, ordinal: u32, dst: DstMatch) -> FlowRule {
    let block = class == PrecedenceClass::HardBlock;
    FlowRule {
        verdict: if block {
            Verdict::Block
        } else {
            Verdict::Permit
        },
        precedence: Precedence { class, ordinal },
        flow: FlowMatch {
            dst,
            dst_port: None,
            protocol: None,
        },
        principal: PrincipalScope(UserPrincipal::from_windows_sid("S-1-5-21-A").ok()),
        app: AppScope::Any,
        egress: EgressConstraint::Any,
        coverage: if block {
            Coverage::AllPackets
        } else {
            Coverage::ConnectOnly
        },
    }
}

#[test]
fn a_subnet_route_flow_lowers_to_one_subnet_filter() {
    let net = Ipv4Addr::new(10, 0, 0, 0);
    let out = lower_route_rules(&plan(vec![network_flow(
        PrecedenceClass::RouteRule(RouteRole::Secondary),
        3,
        DstMatch::SubnetV4 { net, prefix: 8 },
    )]));
    assert_eq!(out.len(), 1, "a subnet must not be dropped: {out:?}");
    let f = &out[0];
    assert_eq!(f.layer, WfpLayerKey::AleAuthConnectV4);
    assert_eq!(f.action, WfpAction::Permit);
    assert_eq!(f.remote_subnet, Some((net, 8)));
    assert!(f.remote_ip.is_none() && f.remote_ip_set.is_empty());
    assert_eq!(f.weight, BASE_SECONDARY + 3);
    assert_eq!(f.user_sid.as_deref(), Some("S-1-5-21-A"));
    assert!(f.validate_layer_conditions().is_ok());
}

#[test]
fn a_subnet_block_flow_lowers_to_both_layers_in_either_family() {
    let v6: Ipv6Addr = "2001:db8::".parse().expect("v6");
    let out = lower_route_rules(&plan(vec![
        network_flow(
            PrecedenceClass::HardBlock,
            0,
            DstMatch::SubnetV4 {
                net: Ipv4Addr::new(203, 0, 113, 0),
                prefix: 24,
            },
        ),
        network_flow(
            PrecedenceClass::HardBlock,
            1,
            DstMatch::SubnetV6 {
                net: v6,
                prefix: 32,
            },
        ),
    ]));
    let layers: Vec<WfpLayerKey> = out.iter().map(|f| f.layer).collect();
    assert_eq!(
        layers,
        vec![
            WfpLayerKey::AleAuthConnectV4,
            WfpLayerKey::OutboundIpPacketV4,
            WfpLayerKey::AleAuthConnectV6,
            WfpLayerKey::OutboundIpPacketV6,
        ]
    );
    assert!(out.iter().all(|f| f.action == WfpAction::Block));
    assert!(out.iter().all(|f| f.validate_layer_conditions().is_ok()));
    assert_eq!(out[2].remote_subnet_v6, Some((v6, 32)));
    assert!(out[1].user_sid.is_none() && out[3].user_sid.is_none());
    let ids: std::collections::HashSet<u64> = out.iter().map(|f| f.id.raw).collect();
    assert_eq!(ids.len(), out.len());
}

#[test]
fn pieces_sharing_a_weight_still_get_distinct_ids() {
    let piece = |third: u8| {
        network_flow(
            PrecedenceClass::RouteRule(RouteRole::Primary),
            255,
            DstMatch::SubnetV4 {
                net: Ipv4Addr::new(10, 0, third, 0),
                prefix: 24,
            },
        )
    };
    let out = lower_route_rules(&plan(vec![piece(1), piece(2)]));
    assert_eq!(out.len(), 2);
    assert_ne!(out[0].id, out[1].id);
}
