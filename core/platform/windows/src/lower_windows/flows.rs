// One flow rule lowered to the filters that express it.

use super::*;

pub(super) fn base_for_class(class: PrecedenceClass) -> Option<u64> {
    match class {
        PrecedenceClass::RouteRule(RouteRole::Primary) => Some(BASE_PRIMARY),
        PrecedenceClass::RouteRule(RouteRole::Secondary) => Some(BASE_SECONDARY),
        PrecedenceClass::HardBlock => Some(BASE_BLOCK),
        // The StrictSecondaryFailClosed default catch-all block sits at
        // the lowest band so any rule-driven `Permit` still wins over it.
        PrecedenceClass::DefaultCatchAll => Some(DEFAULT_BLOCK_WEIGHT),
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
    let user_sid = flow.principal.0.as_ref().map(|p| p.as_stored().to_string());
    let weight = base + u64::from(flow.precedence.ordinal);

    // The fail-closed default block (`StrictSecondaryFailClosed`): a
    // user-scoped ALE `Block` with NO remote condition at the lowest band. Matches
    // `wfp_codegen::default_block_spec`.
    if flow.precedence.class == PrecedenceClass::DefaultCatchAll
        && action == WfpAction::Block
        && matches!(flow.flow.dst, DstMatch::Any)
    {
        return vec![WfpFilterSpec {
            layer: WfpLayerKey::AleAuthConnectV4,
            action: WfpAction::Block,
            remote_ip: None,
            remote_ip_set: Vec::new(),
            remote_ip_set_v6: Vec::new(),
            remote_port: None,
            weight,
            id: derive_catch_all_id(
                user_sid.as_deref(),
                WfpLayerKey::AleAuthConnectV4,
                WfpAction::Block,
                weight,
                // The real catch-all: no conditions, so nothing else to name.
                "",
            ),
            user_sid,
            app_pattern: None,
            local_interface_luid: None,
            remote_subnet: None,
            remote_subnet_v6: None,
            ip_protocol: None,
        }];
    }

    // An `Application` flow lowers to per-exe `ALE_APP_ID` filters (no remote IP,
    // no packet mirror — the packet layer has no app context). The planner puts
    // one path per flow, but iterate defensively.
    if let AppScope::Program { exe_paths, .. } = &flow.app {
        if matches!(flow.flow.dst, DstMatch::Any) {
            return exe_paths
                .iter()
                .map(|path| WfpFilterSpec {
                    layer: WfpLayerKey::AleAuthConnectV4,
                    action,
                    remote_ip: None,
                    remote_ip_set: Vec::new(),
                    remote_ip_set_v6: Vec::new(),
                    remote_port: None,
                    weight,
                    id: derive_app_id(user_sid.as_deref(), action, &path.to_string_lossy(), weight),
                    user_sid: user_sid.clone(),
                    app_pattern: Some(path.to_string_lossy().into_owned()),
                    local_interface_luid: None,
                    remote_subnet: None,
                    remote_subnet_v6: None,
                    ip_protocol: None,
                })
                .collect();
        }
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
