// One flow rule lowered to the filters that express it.

use super::*;

pub(super) fn base_for_class(class: PrecedenceClass) -> Option<u64> {
    match class {
        PrecedenceClass::RouteRule(RouteRole::Primary) => Some(BASE_PRIMARY),
        PrecedenceClass::RouteRule(RouteRole::Secondary) => Some(BASE_SECONDARY),
        PrecedenceClass::HardBlock => Some(BASE_BLOCK),
        _ => None,
    }
}

pub(super) fn lower_flow(flow: &FlowRule) -> Vec<WfpFilterSpec> {
    let Some(base) = base_for_class(flow.precedence.class) else {
        return Vec::new();
    };
    let action = match flow.verdict {
        Verdict::Permit => WfpAction::Permit,
        Verdict::Block => WfpAction::Block,
    };
    let user_sid = user_sid_of(&flow.principal);
    let weight = base + u64::from(flow.precedence.ordinal);

    // An `Application` flow lowers to per-exe `ALE_APP_ID` filters (no remote IP,
    // no packet mirror — the packet layer has no app context). The planner puts
    // one path per flow, but iterate defensively.
    if let AppScope::Program { exe_paths, .. } = &flow.app {
        if matches!(flow.flow.dst, DstMatch::Any) {
            let denies =
                flow.precedence.class == PrecedenceClass::HardBlock && action == WfpAction::Block;
            let slots = nrr_platform_api::enforcement::SLOTS_PER_RULE;
            let loopback_weight = base
                + u64::from(flow.precedence.ordinal) / slots * slots
                + nrr_platform_api::enforcement::DENY_LOOPBACK_SLOT;
            let mut out = Vec::new();
            for path in exe_paths {
                let path = path.to_string_lossy();
                let spec = |layer, action, tag: &str, weight, v4, v6| WfpFilterSpec {
                    layer,
                    action,
                    remote_ip: None,
                    remote_ip_set: Vec::new(),
                    remote_ip_set_v6: Vec::new(),
                    remote_port: None,
                    weight,
                    id: derive_app_id(user_sid.as_deref(), action, &format!("{path}{tag}"), weight),
                    user_sid: user_sid.clone(),
                    app_pattern: Some(path.to_string()),
                    local_interface_luid: None,
                    remote_subnet: v4,
                    remote_subnet_v6: v6,
                    ip_protocol: None,
                    remote_subnet_set: Vec::new(),
                };
                out.push(spec(
                    WfpLayerKey::AleAuthConnectV4,
                    action,
                    "",
                    weight,
                    None,
                    None,
                ));
                // A program deny also closes IPv6 and leaves loopback open.
                if denies {
                    out.push(spec(
                        WfpLayerKey::AleAuthConnectV6,
                        action,
                        "|v6",
                        weight,
                        None,
                        None,
                    ));
                    out.push(spec(
                        WfpLayerKey::AleAuthConnectV4,
                        WfpAction::Permit,
                        "|lo4",
                        loopback_weight,
                        Some((Ipv4Addr::new(127, 0, 0, 0), 8)),
                        None,
                    ));
                    out.push(spec(
                        WfpLayerKey::AleAuthConnectV6,
                        WfpAction::Permit,
                        "|lo6",
                        loopback_weight,
                        None,
                        Some((Ipv6Addr::LOCALHOST, 128)),
                    ));
                }
            }
            return out;
        }
    }

    // A network rule's piece: one subnet filter, mirrored at the packet layer
    // for a Block like a host is.
    if let Some(subnet) = SubnetCondition::of(flow.flow.dst) {
        if !matches!(flow.app, AppScope::Any) {
            return Vec::new();
        }
        let mut out = vec![make_subnet_filter(
            subnet.ale_layer(),
            action,
            subnet,
            weight,
            user_sid,
        )];
        if action == WfpAction::Block && flow.coverage == Coverage::AllPackets {
            out.push(make_subnet_filter(
                subnet.packet_layer(),
                WfpAction::Block,
                subnet,
                weight,
                None,
            ));
        }
        return out;
    }

    let DstMatch::HostV4(ip) = flow.flow.dst else {
        return Vec::new();
    };
    let mut out = vec![make_host_filter(
        WfpLayerKey::AleAuthConnectV4,
        action,
        ip,
        weight,
        user_sid.clone(),
    )];
    // A Block with packet coverage drops the destination at the packet layer
    // too (where ICMP/IGMP/GRE/ESP live). The packet layer exposes no ALE
    // user/app condition, so the mirror MUST carry `user_sid = None`.
    if action == WfpAction::Block && flow.coverage == Coverage::AllPackets {
        out.push(make_host_filter(
            WfpLayerKey::OutboundIpPacketV4,
            WfpAction::Block,
            ip,
            weight,
            None,
        ));
    }
    out
}
