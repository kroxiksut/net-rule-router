// Entry points: a whole plan, and the fake-IP pool, lowered to filters.

use super::*;

/// One plan in, the filters that express it out.
///
/// The five `lower_*` functions above each handle one precedence class; this is
/// the composition the backend applies. Order is the arbitration order — route
/// rules, then the per-destination kill-switch, then the DoH/DoT block, then
/// the catch-all — and it is the property the oracle tests pin, not the ids.
///
/// Routes are deliberately NOT here: they are a different mechanism (the route
/// table, not the filter engine) with a different failure mode, and folding
/// them in would hide a partial apply behind one number.
pub fn lower_plan(plan: &EnforcementPlan, egress: EgressLuids) -> Vec<WfpFilterSpec> {
    let mut out = lower_route_rules(plan);
    out.extend(lower_kill_switch(plan, egress.secondary));
    out.extend(lower_doh_dot_block(plan));
    out.extend(lower_catch_all_kill_switch(plan, egress.secondary));
    out.extend(lower_fake_ip_pool(plan));
    out
}

/// The fake-IP pool band: a subnet permit per family, plus the UDP veto that
/// rides above it while the relay's UDP path is off. Ordinal IS the offset
/// inside the band — the planner emits them in the order the arbitration needs
/// (permit, then the veto that qualifies it).
pub fn lower_fake_ip_pool(plan: &EnforcementPlan) -> Vec<WfpFilterSpec> {
    let mut flows: Vec<&FlowRule> = plan
        .flows
        .iter()
        .filter(|f| f.precedence.class == PrecedenceClass::FakeIpPool)
        .collect();
    flows.sort_by_key(|f| f.precedence.ordinal);

    let mut out = Vec::new();
    for flow in flows {
        let user_sid = flow.principal.0.as_ref().map(|p| p.as_stored().to_string());
        let action = match flow.verdict {
            Verdict::Permit => WfpAction::Permit,
            Verdict::Block => WfpAction::Block,
        };
        let weight = FAKEIP_POOL_PERMIT_BASE + u64::from(flow.precedence.ordinal);
        let proto = flow.flow.protocol.map(l4proto_to_ip_number);
        let (layer, subnet_v4, subnet_v6) = match flow.flow.dst {
            DstMatch::SubnetV4 { net, prefix } => {
                (WfpLayerKey::AleAuthConnectV4, Some((net, prefix)), None)
            }
            DstMatch::SubnetV6 { net, prefix } => {
                (WfpLayerKey::AleAuthConnectV6, None, Some((net, prefix)))
            }
            // The pool is a subnet by construction; anything else in this band
            // is a planner bug, and silently lowering it would hide that.
            _ => continue,
        };
        out.push(WfpFilterSpec {
            layer,
            action,
            remote_ip: None,
            remote_ip_set: Vec::new(),
            remote_ip_set_v6: Vec::new(),
            remote_port: None,
            weight,
            id: derive_subnet_filter_id(user_sid.as_deref(), layer, action, weight),
            user_sid,
            app_pattern: None,
            local_interface_luid: None,
            remote_subnet: subnet_v4,
            remote_subnet_v6: subnet_v6,
            ip_protocol: proto,
        });
    }
    out
}
