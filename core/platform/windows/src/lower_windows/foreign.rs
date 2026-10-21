// Somebody else's tunnel and another VPN's handshake: the permits that keep
// them out of the guard's blocks, and the restatements that keep the user's
// narrower rules above those permits. Mirrors `killswitch_codegen`'s
// `foreign_tunnel_permits`, `doh_foreign_vetoes` and `vpn_handshake`.

use std::collections::BTreeMap;

use nrr_platform_api::enforcement::{
    DOH_FOREIGN_VETO_ORDINAL_BASE, FOREIGN_PIN_VETO_ORDINAL_BASE, VPN_HANDSHAKE_IKE_ORDINAL_BASE,
    VPN_HANDSHAKE_ORDINAL_BASE,
};
use nrr_platform_api::types::MAX_REMOTE_SUBNETS;
use nrr_platform_api::wfp_slotting::pack_v6;

use super::*;

const PROTO_UDP: u8 = 17;
const PROTO_ESP: u8 = 50;
/// First slot of the IKE permits in the handshake band, past every gateway's.
const IKE_SLOT_BASE: u64 = 0x80;

/// A permit through somebody else's tunnel, by the link it names.
pub(super) fn is_foreign_permit(flow: &FlowRule) -> bool {
    flow.precedence.class == PrecedenceClass::CatchAllExempt
        && flow.verdict == Verdict::Permit
        && matches!(
            flow.egress,
            EgressConstraint::OnlyVia(EgressRef::Adapter(_))
        )
}

/// A hard-block flow that restates a guard flow over a foreign tunnel's
/// permits: a pin veto, or the lockdown narrowed to that tunnel. Neither is a
/// rule of the user's, so the rule lowering must not read it as one.
pub(super) fn is_foreign_restatement(flow: &FlowRule) -> bool {
    flow.precedence.class == PrecedenceClass::HardBlock
        && (flow.precedence.ordinal >= FOREIGN_PIN_VETO_ORDINAL_BASE
            || matches!(
                flow.egress,
                EgressConstraint::OnlyVia(EgressRef::Adapter(_))
            ))
}

fn is_pin_veto(flow: &FlowRule) -> bool {
    flow.precedence.class == PrecedenceClass::HardBlock
        && (FOREIGN_PIN_VETO_ORDINAL_BASE..DOH_FOREIGN_VETO_ORDINAL_BASE)
            .contains(&flow.precedence.ordinal)
}

/// Another VPN's handshake permit: its own ordinal range in the exemption class.
pub(super) fn is_vpn_handshake(flow: &FlowRule) -> bool {
    flow.precedence.class == PrecedenceClass::CatchAllExempt
        && flow.verdict == Verdict::Permit
        && flow.egress == EgressConstraint::Any
        && flow.precedence.ordinal >= VPN_HANDSHAKE_ORDINAL_BASE
}

/// A block the guard placed, as opposed to one the user wrote: what a foreign
/// tunnel is spared from. The user's own sit at [`BASE_BLOCK`] and up.
fn is_posture_block(f: &WfpFilterSpec) -> bool {
    f.action == WfpAction::Block
        && match f.layer {
            WfpLayerKey::AleAuthConnectV4 | WfpLayerKey::AleAuthConnectV6 => {
                f.weight < CATCHALL_EXEMPT_BASE
            }
            WfpLayerKey::OutboundTransportV4 => f.weight < PACKET_EXEMPT_BASE,
            WfpLayerKey::OutboundIpPacketV6 => f.weight < BASE_BLOCK,
            _ => false,
        }
}

fn net_contains((net, prefix): (IpAddr, u8), ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            let mask = u32::MAX
                .checked_shl(32 - u32::from(prefix.min(32)))
                .unwrap_or(0);
            u32::from(net) & mask == u32::from(ip) & mask
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            let mask = u128::MAX
                .checked_shl(128 - u32::from(prefix.min(128)))
                .unwrap_or(0);
            u128::from(net) & mask == u128::from(ip) & mask
        }
        _ => false,
    }
}

fn subnet_of(dst: DstMatch) -> Option<(IpAddr, u8)> {
    match dst {
        DstMatch::SubnetV4 { net, prefix } => Some((IpAddr::V4(net), prefix)),
        DstMatch::SubnetV6 { net, prefix } => Some((IpAddr::V6(net), prefix)),
        DstMatch::HostV4(ip) => Some((IpAddr::V4(ip), 32)),
        DstMatch::HostV6(ip) => Some((IpAddr::V6(ip), 128)),
        DstMatch::Any => None,
    }
}

fn digest(seed: &str) -> WfpFilterId {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = FNV_OFFSET;
    for b in seed.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    WfpFilterId::from_raw(h)
}

fn bare(layer: WfpLayerKey, action: WfpAction, weight: u64, id: WfpFilterId) -> WfpFilterSpec {
    WfpFilterSpec {
        layer,
        action,
        remote_ip: None,
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight,
        id,
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
        remote_subnet_set: Vec::new(),
    }
}

/// The principals holding a foreign permit. Forwarded traffic is left out: its
/// permits belong on the forwarding layers, which this lowering does not place
/// them on, so they stay cut rather than open on the wrong layer.
fn scopes_of(plan: &EnforcementPlan) -> Vec<PrincipalScope> {
    let mut scopes: Vec<PrincipalScope> = Vec::new();
    for flow in plan.flows.iter().filter(|f| is_foreign_permit(f)) {
        if flow.principal != PrincipalScope::Forwarded && !scopes.contains(&flow.principal) {
            scopes.push(flow.principal.clone());
        }
    }
    scopes
}

/// Whether `f` is one of `scope`'s filters, as the codegen's per-scope pass
/// would have seen it.
fn emitted_by(scope: &PrincipalScope, ale_sid: Option<&str>, f: &WfpFilterSpec) -> bool {
    if f.layer.supports_ale_scoping() {
        f.user_sid.as_deref() == ale_sid
    } else {
        *scope != PrincipalScope::ServiceAccounts && !f.layer.is_forwarding()
    }
}

/// Lower the foreign-tunnel permits of `plan`, and the pin vetoes that keep a
/// pinned address cut through such a tunnel. `emitted` is everything lowered
/// before them: a tunnel is spared only on a layer a posture block sits on.
///
/// One filter per tunnel per layer, its networks OR'd. A link the caller could
/// not resolve to a LUID is left out: the permit cannot name its egress, and
/// one without it would open the network on every link.
pub fn lower_foreign_tunnels(
    plan: &EnforcementPlan,
    egress: &EgressLuids,
    emitted: &[WfpFilterSpec],
) -> Vec<WfpFilterSpec> {
    let mut out = Vec::new();
    for scope in scopes_of(plan) {
        let ale_sid = user_sid_of(&scope);
        let mine: Vec<&WfpFilterSpec> = emitted
            .iter()
            .filter(|f| emitted_by(&scope, ale_sid.as_deref(), f))
            .collect();
        let mut tunnels: BTreeMap<u64, Vec<(IpAddr, u8)>> = BTreeMap::new();
        for flow in plan
            .flows
            .iter()
            .filter(|f| f.principal == scope && is_foreign_permit(f))
        {
            let EgressConstraint::OnlyVia(EgressRef::Adapter(name)) = &flow.egress else {
                continue;
            };
            let (Some(luid), Some(net)) = (egress.adapter(&name.0), subnet_of(flow.flow.dst))
            else {
                continue;
            };
            tunnels.entry(luid).or_default().push(net);
        }
        let vetoed = plan
            .flows
            .iter()
            .any(|f| f.principal == scope && is_pin_veto(f));
        out.extend(foreign_permits_for(
            &scope,
            ale_sid.as_deref(),
            &mine,
            &tunnels,
            vetoed,
        ));
    }
    out
}

fn foreign_permits_for(
    scope: &PrincipalScope,
    ale_sid: Option<&str>,
    mine: &[&WfpFilterSpec],
    tunnels: &BTreeMap<u64, Vec<(IpAddr, u8)>>,
    vetoed: bool,
) -> Vec<WfpFilterSpec> {
    let seed = ale_sid.unwrap_or("");
    let mut out = Vec::new();
    let mut ale_veto_slot = 0usize;
    let mut transport_veto_slot = 0usize;
    for layer in [
        WfpLayerKey::AleAuthConnectV4,
        WfpLayerKey::OutboundTransportV4,
        WfpLayerKey::AleAuthConnectV6,
        WfpLayerKey::OutboundIpPacketV6,
    ] {
        let ale = layer.supports_ale_scoping();
        if (*scope == PrincipalScope::ServiceAccounts && !ale)
            || !mine.iter().any(|f| f.layer == layer && is_posture_block(f))
        {
            continue;
        }
        let v4 = !layer.is_v6();
        let base = if layer == WfpLayerKey::OutboundTransportV4 {
            PACKET_FOREIGN_TUNNEL_PERMIT_BASE
        } else {
            FOREIGN_TUNNEL_PERMIT_BASE
        };
        let mut permitted: Vec<(u64, (IpAddr, u8))> = Vec::new();
        let family = tunnels.iter().filter_map(|(luid, nets)| {
            let mut nets: Vec<(IpAddr, u8)> = nets
                .iter()
                .copied()
                .filter(|n| n.0.is_ipv4() == v4)
                .collect();
            nets.sort_unstable();
            nets.dedup();
            (!nets.is_empty()).then_some((*luid, nets))
        });
        for (slot, (luid, mut nets)) in family.take(FOREIGN_TUNNEL_MAX_TUNNELS).enumerate() {
            nets.truncate(MAX_REMOTE_SUBNETS);
            let weight = base + slot as u64;
            let seg = nets
                .iter()
                .map(|(net, prefix)| format!("{net}/{prefix}"))
                .collect::<Vec<_>>()
                .join(",");
            let mut spec = bare(
                layer,
                WfpAction::Permit,
                weight,
                digest(&format!(
                    "foreign|{seed}|{}|{luid}|{seg}",
                    nrr_platform_api::wfp_behavioral::layer_ord(layer)
                )),
            );
            if ale {
                spec.user_sid = ale_sid.map(str::to_string);
            }
            spec.local_interface_luid = Some(luid);
            match nets.as_slice() {
                [(IpAddr::V4(net), prefix)] => spec.remote_subnet = Some((*net, *prefix)),
                [(IpAddr::V6(net), prefix)] => spec.remote_subnet_v6 = Some((*net, *prefix)),
                _ => spec.remote_subnet_set = nets.clone(),
            }
            out.push(spec);
            permitted.extend(nets.into_iter().map(|n| (luid, n)));
        }
        if !vetoed {
            continue;
        }
        if ale {
            out.extend(ale_pin_vetoes(
                layer,
                ale_sid,
                mine,
                &permitted,
                &mut ale_veto_slot,
            ));
        } else if layer == WfpLayerKey::OutboundTransportV4 {
            out.extend(transport_pin_vetoes(
                seed,
                mine,
                &permitted,
                &mut transport_veto_slot,
            ));
        }
    }
    out
}

/// A host-only posture block on `layer`: the shape a pin's guard takes.
fn is_pin_block(f: &WfpFilterSpec, layer: WfpLayerKey) -> bool {
    f.layer == layer
        && is_posture_block(f)
        && f.remote_port.is_none()
        && f.app_pattern.is_none()
        && f.remote_subnet.is_none()
        && f.remote_subnet_v6.is_none()
        && f.remote_subnet_set.is_empty()
}

fn hosts_of(f: &WfpFilterSpec) -> impl Iterator<Item = IpAddr> + '_ {
    f.remote_ip
        .into_iter()
        .chain(f.remote_ip_set.iter().copied())
        .map(IpAddr::V4)
        .chain(f.remote_ip_set_v6.iter().copied().map(IpAddr::V6))
}

fn luids_of(permitted: &[(u64, (IpAddr, u8))]) -> Vec<u64> {
    let mut luids: Vec<u64> = permitted.iter().map(|(luid, _)| *luid).collect();
    luids.sort_unstable();
    luids.dedup();
    luids
}

fn inside(permitted: &[(u64, (IpAddr, u8))], luid: u64, ip: IpAddr) -> bool {
    permitted
        .iter()
        .any(|(l, net)| *l == luid && net_contains(*net, ip))
}

/// Per tunnel, a block for the pinned addresses inside its permitted networks,
/// egress through that tunnel only: the narrower rule wins over the network.
fn ale_pin_vetoes(
    layer: WfpLayerKey,
    ale_sid: Option<&str>,
    mine: &[&WfpFilterSpec],
    permitted: &[(u64, (IpAddr, u8))],
    slot: &mut usize,
) -> Vec<WfpFilterSpec> {
    let pinned: Vec<IpAddr> = mine
        .iter()
        .filter(|f| is_pin_block(f, layer))
        .flat_map(|f| hosts_of(f))
        .collect();
    let mut out = Vec::new();
    if pinned.is_empty() {
        return out;
    }
    let seed = ale_sid.unwrap_or("");
    for luid in luids_of(permitted) {
        let members = pinned
            .iter()
            .copied()
            .filter(|ip| inside(permitted, luid, *ip));
        let chunks: Vec<FamilyChunk> = if layer.is_v6() {
            pack_v6(members.filter_map(|ip| match ip {
                IpAddr::V6(a) => Some(a),
                IpAddr::V4(_) => None,
            }))
            .into_iter()
            .map(FamilyChunk::V6)
            .collect()
        } else {
            pack_v4(members.filter_map(|ip| match ip {
                IpAddr::V4(a) => Some(a),
                IpAddr::V6(_) => None,
            }))
            .into_iter()
            .map(FamilyChunk::V4)
            .collect()
        };
        for chunk in chunks {
            if *slot >= FOREIGN_TUNNEL_PIN_VETO_MAX {
                return out;
            }
            let weight = FOREIGN_TUNNEL_PIN_VETO_BASE + *slot as u64;
            *slot += 1;
            let mut spec = bare(
                layer,
                WfpAction::Block,
                weight,
                digest(&format!(
                    "foreign-veto|{seed}|{}|{luid}|{}",
                    nrr_platform_api::wfp_behavioral::layer_ord(layer),
                    chunk.id_seg()
                )),
            );
            spec.user_sid = ale_sid.map(str::to_string);
            spec.local_interface_luid = Some(luid);
            match chunk {
                FamilyChunk::V4(c) => spec.remote_ip_set = c.members,
                FamilyChunk::V6(c) => spec.remote_ip_set_v6 = c.members,
            }
            out.push(spec);
        }
    }
    out
}

/// [`ale_pin_vetoes`] on the transport layer, one protocol at a time: a pin
/// there is a block per protocol, and a protocol the user left unprotected
/// stays open through the tunnel.
fn transport_pin_vetoes(
    seed: &str,
    mine: &[&WfpFilterSpec],
    permitted: &[(u64, (IpAddr, u8))],
    slot: &mut usize,
) -> Vec<WfpFilterSpec> {
    let layer = WfpLayerKey::OutboundTransportV4;
    let mut protocols: Vec<Option<u8>> = mine
        .iter()
        .filter(|f| f.layer == layer && is_posture_block(f))
        .map(|f| f.ip_protocol)
        .collect();
    protocols.sort_unstable();
    protocols.dedup();
    let luids = luids_of(permitted);
    let mut out = Vec::new();
    for proto in protocols {
        let pinned: Vec<Ipv4Addr> = mine
            .iter()
            .filter(|f| is_pin_block(f, layer) && f.ip_protocol == proto)
            .flat_map(|f| {
                f.remote_ip
                    .into_iter()
                    .chain(f.remote_ip_set.iter().copied())
            })
            .collect();
        if pinned.is_empty() {
            continue;
        }
        for luid in &luids {
            let members = pinned
                .iter()
                .copied()
                .filter(|ip| inside(permitted, *luid, IpAddr::V4(*ip)));
            for chunk in pack_v4(members) {
                if *slot >= FOREIGN_TUNNEL_PIN_VETO_MAX {
                    return out;
                }
                let weight = PACKET_FOREIGN_TUNNEL_PIN_VETO_BASE + *slot as u64;
                *slot += 1;
                let mut spec = bare(
                    layer,
                    WfpAction::Block,
                    weight,
                    digest(&format!(
                        "foreign-veto-tr|{seed}|{luid}|{proto:?}|{}",
                        chunk.id_seg()
                    )),
                );
                spec.local_interface_luid = Some(*luid);
                spec.ip_protocol = proto;
                spec.remote_ip_set = chunk.members;
                out.push(spec);
            }
        }
    }
    out
}

/// The DoH/DoT lockdown restated for each foreign tunnel holding a permit at
/// the same layer: a copy of every lockdown block, narrowed to egress through
/// that tunnel, above its permits. `doh` is the lowered lockdown, `emitted`
/// what carries the tunnels' permits.
pub fn lower_doh_foreign_vetoes(
    plan: &EnforcementPlan,
    egress: &EgressLuids,
    doh: &[WfpFilterSpec],
    emitted: &[WfpFilterSpec],
) -> Vec<WfpFilterSpec> {
    let restated: Vec<&FlowRule> = plan
        .flows
        .iter()
        .filter(|f| {
            f.precedence.class == PrecedenceClass::HardBlock
                && f.verdict == Verdict::Block
                && f.precedence.ordinal >= DOH_FOREIGN_VETO_ORDINAL_BASE
        })
        .collect();
    let mut out = Vec::new();
    let Some(first) = restated.first() else {
        return out;
    };
    let sid = user_sid_of(&first.principal);
    let tunnels: Vec<u64> = restated
        .iter()
        .filter_map(|f| match &f.egress {
            EgressConstraint::OnlyVia(EgressRef::Adapter(name)) => egress.adapter(&name.0),
            _ => None,
        })
        .collect();
    for layer in [WfpLayerKey::AleAuthConnectV4, WfpLayerKey::AleAuthConnectV6] {
        let mut luids: Vec<u64> = tunnels
            .iter()
            .copied()
            .filter(|luid| {
                emitted.iter().any(|f| {
                    f.layer == layer
                        && f.action == WfpAction::Permit
                        && f.local_interface_luid == Some(*luid)
                        && (f.user_sid.is_none() || f.user_sid == sid)
                })
            })
            .collect();
        luids.sort_unstable();
        luids.dedup();
        for luid in luids {
            for block in doh.iter().filter(|f| {
                f.layer == layer
                    && f.action == WfpAction::Block
                    && f.local_interface_luid.is_none()
                    && (DOH_BLOCK_BASE..KILLSWITCH_BLOCK_BASE).contains(&f.weight)
            }) {
                if out.len() >= DOH_FOREIGN_VETO_MAX {
                    return out;
                }
                let mut veto = block.clone();
                veto.weight = DOH_FOREIGN_VETO_BASE + out.len() as u64;
                veto.local_interface_luid = Some(luid);
                veto.id = digest(&format!("doh-foreign|{luid}|{:016x}", block.id.raw));
                out.push(veto);
            }
        }
    }
    out
}

/// Lower another VPN's handshake permits, the narrowest each layer can say:
///
/// - ESP on the v4 transport layer, for nobody (the layer has no user). The v6
///   packet layer has no protocol condition, so v6 ESP is not opened.
/// - Each confirmed gateway on its handshake ports, for its user, at ALE; a v6
///   gateway also gets a host permit on the v6 packet layer.
/// - The OS IKE service on UDP 500/4500 at ALE, by image, for the service
///   accounts.
pub fn lower_vpn_handshake(plan: &EnforcementPlan) -> Vec<WfpFilterSpec> {
    let mut flows: Vec<&FlowRule> = plan.flows.iter().filter(|f| is_vpn_handshake(f)).collect();
    flows.sort_by_key(|f| f.precedence.ordinal);
    let (ike, user): (Vec<&FlowRule>, Vec<&FlowRule>) = flows
        .into_iter()
        .partition(|f| f.precedence.ordinal >= VPN_HANDSHAKE_IKE_ORDINAL_BASE);
    let mut out = Vec::new();
    let mut slot = 0u64;
    for (n, flow) in user.iter().enumerate() {
        let sid = user_sid_of(&flow.principal);
        let seed = sid.clone().unwrap_or_default();
        let proto = flow.flow.protocol.map(l4proto_to_ip_number);
        match (proto, flow.flow.dst, flow.flow.dst_port) {
            (Some(PROTO_ESP), DstMatch::Any, None) => {
                let mut spec = bare(
                    WfpLayerKey::OutboundTransportV4,
                    WfpAction::Permit,
                    PACKET_VPN_HANDSHAKE_PERMIT_BASE,
                    digest(&format!("vpn-esp|{seed}")),
                );
                spec.ip_protocol = Some(PROTO_ESP);
                out.push(spec);
            }
            (Some(PROTO_UDP), dst @ (DstMatch::HostV4(_) | DstMatch::HostV6(_)), Some(port)) => {
                let layer = match dst {
                    DstMatch::HostV6(_) => WfpLayerKey::AleAuthConnectV6,
                    _ => WfpLayerKey::AleAuthConnectV4,
                };
                let mut spec = bare(
                    layer,
                    WfpAction::Permit,
                    VPN_HANDSHAKE_PERMIT_BASE + slot,
                    digest(&format!("vpn-gw|{seed}|{dst:?}|{port}")),
                );
                slot += 1;
                match dst {
                    DstMatch::HostV4(ip) => spec.remote_ip = Some(ip),
                    DstMatch::HostV6(ip) => spec.remote_subnet_v6 = Some((ip, 128)),
                    _ => {}
                }
                spec.remote_port = Some(port);
                spec.ip_protocol = Some(PROTO_UDP);
                spec.user_sid = sid;
                out.push(spec);
                // After a v6 gateway's last port: the packet layer can name
                // the host and nothing narrower.
                let last_of_gateway = user.get(n + 1).is_none_or(|next| next.flow.dst != dst);
                if let (DstMatch::HostV6(ip), true) = (dst, last_of_gateway) {
                    let mut spec = bare(
                        WfpLayerKey::OutboundIpPacketV6,
                        WfpAction::Permit,
                        VPN_HANDSHAKE_PERMIT_BASE + slot,
                        digest(&format!("vpn-gw-v6-pkt|{seed}|{ip}")),
                    );
                    slot += 1;
                    spec.remote_subnet_v6 = Some((ip, 128));
                    out.push(spec);
                }
            }
            _ => {}
        }
    }
    let images: Vec<String> = ike
        .first()
        .map(|f| match &f.app {
            AppScope::Program { exe_paths, .. } => exe_paths
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect(),
            AppScope::Any => Vec::new(),
        })
        .unwrap_or_default();
    let mut slot = IKE_SLOT_BASE;
    for image in &images {
        for flow in &ike {
            let layer = if matches!(flow.flow.dst, DstMatch::SubnetV6 { .. }) {
                WfpLayerKey::AleAuthConnectV6
            } else {
                WfpLayerKey::AleAuthConnectV4
            };
            let sid = user_sid_of(&flow.principal);
            let mut spec = bare(
                layer,
                WfpAction::Permit,
                VPN_HANDSHAKE_PERMIT_BASE + slot,
                digest(&format!(
                    "vpn-ike|{}|{image}|{:?}|{}",
                    sid.as_deref().unwrap_or(""),
                    flow.flow.dst_port,
                    nrr_platform_api::wfp_behavioral::layer_ord(layer)
                )),
            );
            slot += 1;
            spec.remote_port = flow.flow.dst_port;
            spec.ip_protocol = flow.flow.protocol.map(l4proto_to_ip_number);
            spec.user_sid = sid;
            spec.app_pattern = Some(image.clone());
            out.push(spec);
        }
    }
    out
}
