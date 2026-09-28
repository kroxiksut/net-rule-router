// DoH/DoT lockdown and the app-scoped permits and blocks.

use super::*;

/// Lower the DoH/DoT lockdown plan
/// ([`enforcement_planner::plan_doh_dot_block`]) to WFP filters. Host
/// [`PrecedenceClass::DohBlock`] flows of either family are grouped by
/// `(dst_port, protocol)` and packed — one ALE-connect `Block` per chunk — and
/// `Any` flows (the global DoT cut) become one unconditional block per family,
/// because a WFP filter lives at one family's layer. Reproduces the packed
/// `killswitch_codegen::doh_dot_block_filters`.
pub fn lower_doh_dot_block(plan: &EnforcementPlan) -> Vec<WfpFilterSpec> {
    // Grouped by port, protocols in first-seen order — emission then walks,
    // per family, chunk × protocol with one running weight, then the global
    // (`Any`) cuts: the codegen's exact weight order, which the arbitration
    // oracle pins.
    type PortGroup = (Option<u16>, Vec<Option<u8>>, Vec<IpAddr>);
    let mut port_groups: Vec<PortGroup> = Vec::new();
    let mut any_cuts: Vec<(Option<u16>, Option<u8>, Option<String>)> = Vec::new();
    let mut set_sid: Option<String> = None;
    for flow in &plan.flows {
        if flow.precedence.class != PrecedenceClass::DohBlock || flow.verdict != Verdict::Block {
            continue;
        }
        let user_sid = flow.principal.0.as_ref().map(|p| p.as_stored().to_string());
        let proto = flow.flow.protocol.map(l4proto_to_ip_number);
        let ip = match flow.flow.dst {
            DstMatch::HostV4(ip) => IpAddr::V4(ip),
            DstMatch::HostV6(ip) => IpAddr::V6(ip),
            DstMatch::Any => {
                any_cuts.push((flow.flow.dst_port, proto, user_sid));
                continue;
            }
            _ => continue, // DoH lockdown only emits hosts / Any
        };
        if set_sid.is_none() {
            set_sid = user_sid;
        }
        let port = flow.flow.dst_port;
        let at = port_groups
            .iter()
            .position(|(p, _, _)| *p == port)
            .unwrap_or_else(|| {
                port_groups.push((port, Vec::new(), Vec::new()));
                port_groups.len() - 1
            });
        let group = &mut port_groups[at];
        if !group.1.contains(&proto) {
            group.1.push(proto);
        }
        group.2.push(ip);
    }
    let mut out = Vec::new();
    for layer in [WfpLayerKey::AleAuthConnectV4, WfpLayerKey::AleAuthConnectV6] {
        let mut weight = DOH_BLOCK_BASE;
        for (port, protos, ips) in &port_groups {
            for chunk in pack_both(ips.iter().copied())
                .iter()
                .filter(|c| chunk_layer(c) == layer)
            {
                for proto in protos {
                    out.push(doh_port_block(
                        layer,
                        Some(chunk),
                        *port,
                        *proto,
                        weight,
                        set_sid.clone(),
                    ));
                    weight += 1;
                }
            }
        }
        for (port, proto, user_sid) in &any_cuts {
            out.push(doh_port_block(
                layer,
                None,
                *port,
                *proto,
                weight,
                user_sid.clone(),
            ));
            weight += 1;
        }
    }
    out
}

fn chunk_layer(chunk: &FamilyChunk) -> WfpLayerKey {
    match chunk {
        FamilyChunk::V4(_) => WfpLayerKey::AleAuthConnectV4,
        FamilyChunk::V6(_) => WfpLayerKey::AleAuthConnectV6,
    }
}

/// ALE-connect `Block` at `layer` narrowed to `(chunk?, port, proto)`. Mirrors
/// the packed `killswitch_codegen::doh_port_block`.
pub(super) fn doh_port_block(
    layer: WfpLayerKey,
    scope: Option<&FamilyChunk>,
    remote_port: Option<u16>,
    proto: Option<u8>,
    weight: u64,
    user_sid: Option<String>,
) -> WfpFilterSpec {
    let seg = scope
        .map(FamilyChunk::id_seg)
        .unwrap_or_else(|| "any".to_string());
    let id = derive_set_id(
        user_sid.as_deref(),
        layer,
        WfpAction::Block,
        &format!("doh|{seg}"),
        weight,
    );
    let (remote_ip_set, remote_ip_set_v6) = match scope {
        Some(FamilyChunk::V4(c)) => (c.members.clone(), Vec::new()),
        Some(FamilyChunk::V6(c)) => (Vec::new(), c.members.clone()),
        None => (Vec::new(), Vec::new()),
    };
    WfpFilterSpec {
        layer,
        action: WfpAction::Block,
        remote_ip: None,
        remote_ip_set,
        remote_ip_set_v6,
        remote_port,
        weight,
        id,
        user_sid,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: proto,
    }
}

/// The `ALE_APP_ID` pattern a flow carries (the first resolved exe path / raw
/// pattern), or `None` for [`AppScope::Any`].
pub(super) fn app_pattern_of(app: &AppScope) -> Option<String> {
    match app {
        AppScope::Any => None,
        AppScope::Program { exe_paths, .. } => {
            exe_paths.first().map(|p| p.to_string_lossy().into_owned())
        }
    }
}

/// ALE-connect per-app egress-conditional `Permit` — allow `pattern`'s process
/// only while it egresses `luid`. Mirrors `killswitch_codegen::permit_app_via_secondary`.
pub(super) fn ale_app_egress_permit(
    pattern: &str,
    luid: u64,
    weight: u64,
    user_sid: Option<String>,
) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Permit,
        remote_ip: None,
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight,
        id: derive_app_id(user_sid.as_deref(), WfpAction::Permit, pattern, weight),
        user_sid,
        app_pattern: Some(pattern.to_string()),
        local_interface_luid: Some(luid),
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

/// ALE-connect per-app unconditional `Block` (proto-agnostic). Mirrors
/// `killswitch_codegen::block_app_off_secondary` / `ale_block_app`.
pub(super) fn ale_app_block(pattern: &str, weight: u64, user_sid: Option<String>) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip: None,
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight,
        id: derive_app_id(user_sid.as_deref(), WfpAction::Block, pattern, weight),
        user_sid,
        app_pattern: Some(pattern.to_string()),
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

/// The WFP `FWPM_CONDITION_IP_PROTOCOL` number (IANA) for a neutral [`L4Proto`].
/// The packet-layer kill-switch narrows a filter to exactly one protocol; the
/// numbers are the same the current `killswitch_codegen` uses literally.
pub(super) fn l4proto_to_ip_number(proto: L4Proto) -> u8 {
    match proto {
        L4Proto::Icmp => 1,
        L4Proto::Igmp => 2,
        L4Proto::Tcp => 6,
        L4Proto::Udp => 17,
        L4Proto::Gre => 47,
        L4Proto::Esp => 50,
        L4Proto::IcmpV6 => 58,
        L4Proto::Other(n) => n,
    }
}

/// Pick the below-ALE layer a filter can legally live at: a
/// protocol-narrowed condition needs `OUTBOUND_TRANSPORT_V4` (the only
/// below-ALE layer exposing `FWPM_CONDITION_IP_PROTOCOL`); an agnostic filter
/// stays at the packet layer, which sees kernel-injected traffic the
/// transport stack never carries.
pub(super) fn below_ale_layer_for(proto: Option<u8>) -> WfpLayerKey {
    if proto.is_some() {
        WfpLayerKey::OutboundTransportV4
    } else {
        WfpLayerKey::OutboundIpPacketV4
    }
}

/// Below-ALE unconditional `Permit` for `ip` (narrowed to `proto`) — lets an
/// UN-selected protocol escape the "Other" block-all. `user_sid = None`, no egress
/// condition. Mirrors `killswitch_codegen::packet_permit`. Layer picked by
/// [`below_ale_layer_for`].
pub(super) fn packet_permit(ip: Ipv4Addr, weight: u64, proto: Option<u8>) -> WfpFilterSpec {
    let layer = below_ale_layer_for(proto);
    WfpFilterSpec {
        layer,
        action: WfpAction::Permit,
        remote_ip: Some(ip),
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight,
        id: derive_filter_id(None, layer, WfpAction::Permit, ip, weight),
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: proto,
    }
}
