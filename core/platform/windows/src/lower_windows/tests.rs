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
        route_flow(RouteRole::Primary, 0, Ipv4Addr::new(1, 1, 1, 1)),
        route_flow(RouteRole::Secondary, 0, Ipv4Addr::new(2, 2, 2, 2)),
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
    assert_ne!(base("1.1.1.1|53"), base("8.8.8.8|53"));
    assert_ne!(base("1.1.1.1|53"), base("1.1.1.1|443"));
    // Same inputs still give the same id — the whole point of deriving it.
    assert_eq!(base("1.1.1.1|53"), base("1.1.1.1|53"));
}
