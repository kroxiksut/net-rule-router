//! One ordered emitter for everything the cut must not take with it.
//!
//! Loopback, the link's own upkeep, DHCP, the local subnets, the addresses a
//! tunnel needs to come back up, the networks of tunnels beside ours — plus the
//! per-shape permits the callers emit them with. One place, so a fix to the
//! floor is a fix to every block that needs it.

use std::net::{IpAddr, Ipv4Addr};

use nrr_platform_api::types::{WfpAction, WfpFilterSpec, WfpLayerKey};

use super::*;
use crate::wfp_bands::{
    DOH_BLOCK_BASE, DOH_FOREIGN_VETO_BASE, DOH_FOREIGN_VETO_MAX, FOREIGN_TUNNEL_MAX_NETWORKS,
    FOREIGN_TUNNEL_MAX_TUNNELS, FOREIGN_TUNNEL_PERMIT_BASE, FOREIGN_TUNNEL_PIN_VETO_BASE,
    FOREIGN_TUNNEL_PIN_VETO_MAX, KILLSWITCH_BLOCK_BASE, PACKET_FOREIGN_TUNNEL_PERMIT_BASE,
    PACKET_FOREIGN_TUNNEL_PIN_VETO_BASE, PACKET_V6_EXEMPT_BASE,
};

/// The floor a block with no destination condition needs: loopback, the link's
/// own upkeep, the tunnel servers and the local subnets. A per-app block matches
/// everything its program sends off the tunnel, so without this a pinned app
/// cannot reach 127.0.0.1, its router or a NAS. Same ids as the blanket
/// postures' floor, so a caller can tell one already carries it.
#[must_use]
pub fn destination_less_floor(sid: &str, exemptions: &FailClosedExemptions) -> Vec<WfpFilterSpec> {
    let mut weight = CATCHALL_EXEMPT_BASE;
    let mut out = base_ale_exemptions(sid, &exemptions.bootstrap_server_ips, &mut weight);
    for (net, prefix) in &exemptions.local_subnets {
        out.push(exempt_subnet(sid, *net, *prefix, weight));
        weight += 1;
    }
    out
}

/// The exemptions BOTH block-everything postures carry, in one place.
///
/// The catch-all (tunnel up, everything off-tunnel dropped) and the fail-closed
/// block-all (tunnel gone) are different postures with the same floor: cut
/// these and the machine loses local IPC, DHCP, name resolution on the LAN and
/// the tunnel's own handshake. They were written out twice, and a fix to one
/// list was a fix to one posture.
///
/// `weight` is advanced past what was emitted, so a caller can continue its own
/// numbering after the shared block.
/// `pub(super)` because the emitters moved out of `killswitch_codegen` and it
/// is now the caller.
pub(super) fn base_ale_exemptions(
    sid: &str,
    bootstrap_server_ips: &[Ipv4Addr],
    weight: &mut u64,
) -> Vec<WfpFilterSpec> {
    let mut out = Vec::new();
    // Loopback (local IPC, the GUI-service pipe, DNS stub resolvers).
    out.push(exempt_subnet(sid, Ipv4Addr::new(127, 0, 0, 0), 8, *weight));
    *weight += 1;
    // Link-local / APIPA.
    out.push(exempt_subnet(
        sid,
        Ipv4Addr::new(169, 254, 0, 0),
        16,
        *weight,
    ));
    *weight += 1;
    // Limited broadcast (DHCP discover/request).
    out.push(exempt_host(sid, Ipv4Addr::BROADCAST, *weight));
    *weight += 1;
    // The local network control block (mDNS/LLMNR/IGMP).
    out.push(exempt_subnet(sid, V4_LOCAL_NETWORK_CONTROL, 24, *weight));
    *weight += 1;
    // Known VPN server(s), so the tunnel can (re)establish.
    for ip in bootstrap_server_ips {
        out.push(exempt_host(sid, *ip, *weight));
        *weight += 1;
    }
    out
}

/// Packet-layer twin of [`base_ale_exemptions`]. The named-protocol blocks live
/// at `OUTBOUND_TRANSPORT_V4`, which has no `IP_PROTOCOL` condition at the
/// packet layer, so that layer needs its own copy of the same floor.
/// `pub(super)` because the emitters moved out of `killswitch_codegen` and it
/// is now the caller.
pub(super) fn base_packet_exemptions(
    sid: &str,
    layer: WfpLayerKey,
    bootstrap_server_ips: &[Ipv4Addr],
    weight: &mut u64,
) -> Vec<WfpFilterSpec> {
    let mut out = Vec::new();
    out.push(packet_exempt_subnet(
        sid,
        layer,
        Ipv4Addr::new(127, 0, 0, 0),
        8,
        *weight,
    ));
    *weight += 1;
    out.push(packet_exempt_subnet(
        sid,
        layer,
        Ipv4Addr::new(169, 254, 0, 0),
        16,
        *weight,
    ));
    *weight += 1;
    out.push(packet_exempt_host(sid, layer, Ipv4Addr::BROADCAST, *weight));
    *weight += 1;
    out.push(packet_exempt_subnet(
        sid,
        layer,
        V4_LOCAL_NETWORK_CONTROL,
        24,
        *weight,
    ));
    *weight += 1;
    for ip in bootstrap_server_ips {
        out.push(packet_exempt_host(sid, layer, *ip, *weight));
        *weight += 1;
    }
    out
}

/// Exemption permit: allow any flow egressing the secondary adapter interface.
/// `pub(super)` because the emitters moved out of `killswitch_codegen` and it
/// is now the caller.
pub(super) fn exempt_egress(sid: &str, secondary_luid: u64, weight: u64) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Permit,
        remote_ip: None,
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight,
        id: filter_id_for(
            sid,
            KILLSWITCH_ROLE,
            &permit_luid_seg(secondary_luid),
            "ks-ca-egress",
            "secondary",
        ),
        user_sid: Some(sid.to_string()),
        app_pattern: None,
        local_interface_luid: Some(secondary_luid),
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
        remote_subnet_set: Vec::new(),
    }
}

/// Permits that keep somebody else's tunnels out of every posture block among
/// `emitted`: egress through the tunnel to the networks its own routes carry,
/// on each layer a posture block sits on. One filter per tunnel per layer, the
/// networks OR'd as same-field conditions.
///
/// Narrow on purpose, in every posture. A tunnel that also holds a default
/// route would, under an any-destination permit, carry the user's protected
/// traffic once ours is down; spared to its own networks, it keeps what it was
/// carrying and nothing more. Past [`FOREIGN_TUNNEL_MAX_NETWORKS`] per tunnel
/// and family (or [`FOREIGN_TUNNEL_MAX_TUNNELS`] tunnels) the rest stay cut.
/// The user's own Blocks outrank every permit here.
///
/// The transport and v6 packet layers have no user condition, so their permits
/// are machine-wide by construction. They stay as narrow as the layer allows:
/// the tunnel's own networks AND its egress interface, which only the routes of
/// the user who runs that tunnel reach.
#[must_use]
pub fn foreign_tunnel_permits(
    sid: &str,
    emitted: &[WfpFilterSpec],
    networks: &[ForeignTunnelNetwork],
    own: u64,
) -> Vec<WfpFilterSpec> {
    foreign_tunnel_permits_counted(sid, emitted, networks, own).filters
}

/// What [`foreign_tunnel_permits_counted`] emitted, and how much it had to leave
/// out.
#[derive(Debug, Default)]
pub struct ForeignPermits {
    pub filters: Vec<WfpFilterSpec>,
    /// Networks past the per-tunnel cap (or on a tunnel past the tunnel cap),
    /// IPv4 and IPv6: they stay cut. The caller says so once; codegen stays pure.
    pub cut: (usize, usize),
}

/// [`foreign_tunnel_permits`] with the cut count.
///
/// An address the user pinned to our tunnel inside a permitted network is cut
/// for egress through that tunnel: the narrower rule wins over the network.
#[must_use]
pub fn foreign_tunnel_permits_counted(
    sid: &str,
    emitted: &[WfpFilterSpec],
    networks: &[ForeignTunnelNetwork],
    own: u64,
) -> ForeignPermits {
    let mut out = Vec::new();
    let mut cut = (0usize, 0usize);
    let mut vetoes = VetoSlots::default();
    let mut transport_vetoes = VetoSlots::default();
    for layer in [
        WfpLayerKey::AleAuthConnectV4,
        WfpLayerKey::OutboundTransportV4,
        WfpLayerKey::AleAuthConnectV6,
        WfpLayerKey::OutboundTransportV6,
    ] {
        if !emitted
            .iter()
            .any(|f| f.layer == layer && is_posture_block(f))
        {
            continue;
        }
        let v4 = matches!(
            layer,
            WfpLayerKey::AleAuthConnectV4 | WfpLayerKey::OutboundTransportV4
        );
        let base = if layer == WfpLayerKey::OutboundTransportV4 {
            PACKET_FOREIGN_TUNNEL_PERMIT_BASE
        } else {
            FOREIGN_TUNNEL_PERMIT_BASE
        };
        // One permit per tunnel: its networks, deduplicated and bounded.
        let mut by_tunnel: std::collections::BTreeMap<u64, Vec<&ForeignTunnelNetwork>> =
            std::collections::BTreeMap::new();
        for n in networks
            .iter()
            .filter(|n| n.luid != 0 && n.luid != own && n.network.is_ipv4() == v4)
        {
            by_tunnel.entry(n.luid).or_default().push(n);
        }
        let mut permitted: Vec<&ForeignTunnelNetwork> = Vec::new();
        let mut cut_here = 0usize;
        for (slot, (luid, mut nets)) in by_tunnel.into_iter().enumerate() {
            nets.sort_unstable_by_key(|n| n.network);
            nets.dedup_by_key(|n| n.network);
            if slot >= FOREIGN_TUNNEL_MAX_TUNNELS {
                cut_here += nets.len();
                continue;
            }
            cut_here += nets.len().saturating_sub(FOREIGN_TUNNEL_MAX_NETWORKS);
            nets.truncate(FOREIGN_TUNNEL_MAX_NETWORKS);
            out.push(foreign_tunnel_permit(
                sid,
                layer,
                luid,
                &nets,
                base + slot as u64,
            ));
            permitted.extend(nets);
        }
        // The ALE layers see each family once; the transport layers repeat it.
        match layer {
            WfpLayerKey::AleAuthConnectV4 => cut.0 = cut_here,
            WfpLayerKey::AleAuthConnectV6 => cut.1 = cut_here,
            _ => {}
        }
        if matches!(
            layer,
            WfpLayerKey::AleAuthConnectV4 | WfpLayerKey::AleAuthConnectV6
        ) {
            out.extend(pin_vetoes(sid, layer, emitted, &permitted, &mut vetoes));
        } else if layer == WfpLayerKey::OutboundTransportV4 {
            out.extend(transport_pin_vetoes(
                sid,
                emitted,
                &permitted,
                &mut transport_vetoes,
            ));
        }
    }
    ForeignPermits { filters: out, cut }
}

/// Next free weight slot in the veto band.
#[derive(Default)]
struct VetoSlots(usize);

/// Blocks, per tunnel, for the addresses `emitted` pins that lie inside one of
/// its permitted networks. A pin is a host-only block with no port or program,
/// the shape the per-destination guards emit.
fn pin_vetoes(
    sid: &str,
    layer: WfpLayerKey,
    emitted: &[WfpFilterSpec],
    permitted: &[&ForeignTunnelNetwork],
    slots: &mut VetoSlots,
) -> Vec<WfpFilterSpec> {
    use nrr_platform_api::wfp_slotting::{pack_v4, pack_v6};
    let v6 = layer == WfpLayerKey::AleAuthConnectV6;
    let pinned: Vec<IpAddr> = emitted
        .iter()
        .filter(|f| {
            f.layer == layer
                && is_posture_block(f)
                && f.remote_port.is_none()
                && f.app_pattern.is_none()
                && f.remote_subnet.is_none()
                && f.remote_subnet_v6.is_none()
                && f.remote_subnet_set.is_empty()
        })
        .flat_map(|f| {
            f.remote_ip
                .into_iter()
                .chain(f.remote_ip_set.iter().copied())
                .map(IpAddr::V4)
                .chain(f.remote_ip_set_v6.iter().copied().map(IpAddr::V6))
        })
        .collect();
    if pinned.is_empty() {
        return Vec::new();
    }
    let mut luids: Vec<u64> = permitted.iter().map(|n| n.luid).collect();
    luids.sort_unstable();
    luids.dedup();
    let mut out = Vec::new();
    for luid in luids {
        let inside = pinned.iter().copied().filter(|ip| {
            permitted
                .iter()
                .any(|n| n.luid == luid && n.network.contains(*ip))
        });
        let spec = |weight, kind: &str, seg: String| WfpFilterSpec {
            layer,
            action: WfpAction::Block,
            remote_ip: None,
            remote_ip_set: Vec::new(),
            remote_ip_set_v6: Vec::new(),
            remote_port: None,
            weight,
            id: filter_id_for(sid, KILLSWITCH_ROLE, &permit_luid_seg(luid), kind, &seg),
            user_sid: Some(sid.to_string()),
            app_pattern: None,
            local_interface_luid: Some(luid),
            remote_subnet: None,
            remote_subnet_v6: None,
            ip_protocol: None,
            remote_subnet_set: Vec::new(),
        };
        if v6 {
            let members = inside.filter_map(|ip| match ip {
                IpAddr::V6(a) => Some(a),
                IpAddr::V4(_) => None,
            });
            for chunk in pack_v6(members) {
                if slots.0 >= FOREIGN_TUNNEL_PIN_VETO_MAX {
                    return out;
                }
                let weight = FOREIGN_TUNNEL_PIN_VETO_BASE + slots.0 as u64;
                slots.0 += 1;
                let mut s = spec(weight, "ks-foreign-veto-v6", chunk.id_seg());
                s.remote_ip_set_v6 = chunk.members;
                out.push(s);
            }
        } else {
            let members = inside.filter_map(|ip| match ip {
                IpAddr::V4(a) => Some(a),
                IpAddr::V6(_) => None,
            });
            for chunk in pack_v4(members) {
                if slots.0 >= FOREIGN_TUNNEL_PIN_VETO_MAX {
                    return out;
                }
                let weight = FOREIGN_TUNNEL_PIN_VETO_BASE + slots.0 as u64;
                slots.0 += 1;
                let mut s = spec(weight, "ks-foreign-veto", chunk.id_seg());
                s.remote_ip_set = chunk.members;
                out.push(s);
            }
        }
    }
    out
}

/// [`pin_vetoes`] for the transport layer, where the foreign permit also
/// covers ICMP and the other non-TCP/UDP protocols. A pin there is a block per
/// protocol, so each veto keeps the protocol of the block it carves out of: a
/// protocol the user left unprotected stays open through the tunnel.
fn transport_pin_vetoes(
    sid: &str,
    emitted: &[WfpFilterSpec],
    permitted: &[&ForeignTunnelNetwork],
    slots: &mut VetoSlots,
) -> Vec<WfpFilterSpec> {
    use nrr_platform_api::wfp_slotting::pack_v4;
    let layer = WfpLayerKey::OutboundTransportV4;
    let mut protocols: Vec<Option<u8>> = emitted
        .iter()
        .filter(|f| f.layer == layer && is_posture_block(f))
        .map(|f| f.ip_protocol)
        .collect();
    protocols.sort_unstable();
    protocols.dedup();
    let mut luids: Vec<u64> = permitted.iter().map(|n| n.luid).collect();
    luids.sort_unstable();
    luids.dedup();
    let mut out = Vec::new();
    for proto in protocols {
        let pinned: Vec<Ipv4Addr> = emitted
            .iter()
            .filter(|f| {
                f.layer == layer
                    && is_posture_block(f)
                    && f.ip_protocol == proto
                    && f.remote_port.is_none()
                    && f.app_pattern.is_none()
                    && f.remote_subnet.is_none()
                    && f.remote_subnet_v6.is_none()
                    && f.remote_subnet_set.is_empty()
            })
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
            let inside = pinned.iter().copied().filter(|ip| {
                permitted
                    .iter()
                    .any(|n| n.luid == *luid && n.network.contains(IpAddr::V4(*ip)))
            });
            for chunk in pack_v4(inside) {
                if slots.0 >= FOREIGN_TUNNEL_PIN_VETO_MAX {
                    return out;
                }
                let weight = PACKET_FOREIGN_TUNNEL_PIN_VETO_BASE + slots.0 as u64;
                slots.0 += 1;
                out.push(WfpFilterSpec {
                    layer,
                    action: WfpAction::Block,
                    remote_ip: None,
                    remote_ip_set: chunk.members.clone(),
                    remote_ip_set_v6: Vec::new(),
                    remote_port: None,
                    weight,
                    id: filter_id_for(
                        sid,
                        KILLSWITCH_ROLE,
                        &permit_luid_seg(*luid),
                        "ks-foreign-veto-tr",
                        &format!("{}-{}", proto.map_or(-1, i32::from), chunk.id_seg()),
                    ),
                    user_sid: None,
                    app_pattern: None,
                    local_interface_luid: Some(*luid),
                    remote_subnet: None,
                    remote_subnet_v6: None,
                    ip_protocol: proto,
                    remote_subnet_set: Vec::new(),
                });
            }
        }
    }
    out
}

/// Whether `emitted` holds a posture block [`foreign_tunnel_permits`] would
/// spare a tunnel from.
#[must_use]
pub fn has_posture_block(emitted: &[WfpFilterSpec]) -> bool {
    emitted.iter().any(is_posture_block)
}

/// A block the guard placed, as opposed to one the user wrote. The
/// user's sit at [`crate::wfp_bands::BASE_BLOCK`] and above on ALE, and their packet mirrors
/// on the packet layers, where the guard places nothing.
fn is_posture_block(f: &WfpFilterSpec) -> bool {
    f.action == WfpAction::Block
        && match f.layer {
            WfpLayerKey::AleAuthConnectV4 | WfpLayerKey::AleAuthConnectV6 => {
                f.weight < CATCHALL_EXEMPT_BASE
            }
            WfpLayerKey::OutboundTransportV4 => f.weight < PACKET_EXEMPT_BASE,
            WfpLayerKey::OutboundTransportV6 => f.weight < PACKET_V6_EXEMPT_BASE,
            _ => false,
        }
}

/// Egress through `luid` to any of `nets`, on `layer`. Below ALE there is no
/// user id, so those carry none: such a layer cannot tell users apart, and what
/// narrows the permit there is the pair of conditions it does have, the
/// tunnel's networks and its interface.
fn foreign_tunnel_permit(
    sid: &str,
    layer: WfpLayerKey,
    luid: u64,
    nets: &[&ForeignTunnelNetwork],
    weight: u64,
) -> WfpFilterSpec {
    let (kind, ale) = match layer {
        WfpLayerKey::AleAuthConnectV4 => ("ks-foreign-ale", true),
        WfpLayerKey::AleAuthConnectV6 => ("ks-foreign-ale-v6", true),
        WfpLayerKey::OutboundTransportV4 => ("ks-foreign-tr", false),
        _ => ("ks-foreign-pkt-v6", false),
    };
    let blocks: Vec<(IpAddr, u8)> = nets
        .iter()
        .map(|n| (n.network.network(), n.network.prefix_len()))
        .collect();
    // One network keeps the single-subnet spelling and its id; several are a set.
    let (remote_subnet, remote_subnet_v6, remote_subnet_set, seg) = match blocks.as_slice() {
        [(IpAddr::V4(net), prefix)] => (
            Some((*net, *prefix)),
            None,
            Vec::new(),
            format!("{net}/{prefix}"),
        ),
        [(IpAddr::V6(net), prefix)] => (
            None,
            Some((*net, *prefix)),
            Vec::new(),
            format!("{net}/{prefix}"),
        ),
        _ => {
            let seg = blocks
                .iter()
                .map(|(net, prefix)| format!("{net}/{prefix}"))
                .collect::<Vec<_>>()
                .join(",");
            (None, None, blocks.clone(), format!("set-{seg}"))
        }
    };
    WfpFilterSpec {
        layer,
        action: WfpAction::Permit,
        remote_ip: None,
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight,
        id: filter_id_for(sid, KILLSWITCH_ROLE, &permit_luid_seg(luid), kind, &seg),
        user_sid: ale.then(|| sid.to_string()),
        app_pattern: None,
        local_interface_luid: Some(luid),
        remote_subnet,
        remote_subnet_v6,
        remote_subnet_set,
        ip_protocol: None,
    }
}

/// Every tunnel beside ours that is named at all: the ones with a route of
/// their own and the ones only listed.
#[must_use]
pub fn foreign_luids_of(luids: &[u64], networks: &[ForeignTunnelNetwork]) -> Vec<u64> {
    let mut all: Vec<u64> = luids
        .iter()
        .copied()
        .chain(networks.iter().map(|n| n.luid))
        .collect();
    all.sort_unstable();
    all.dedup();
    all
}

/// The DoH/DoT lockdown restated for each foreign tunnel that holds a permit at
/// the same layer: a copy of every lockdown block, narrowed to egress through
/// that tunnel and placed above the tunnel's permits. A corporate tunnel can
/// route a public resolver, and without this the lockdown would end at its edge.
/// Past [`DOH_FOREIGN_VETO_MAX`] the rest are left out (the lockdown itself
/// still stands on every other egress).
///
/// `foreign_luids` are the tunnels beside ours, `emitted` holds their permits
/// and `doh` the lockdown blocks of `sid`.
#[must_use]
pub fn doh_foreign_vetoes(
    sid: &str,
    doh: &[WfpFilterSpec],
    emitted: &[WfpFilterSpec],
    foreign_luids: &[u64],
    own: u64,
) -> Vec<WfpFilterSpec> {
    let mut out = Vec::new();
    for layer in [WfpLayerKey::AleAuthConnectV4, WfpLayerKey::AleAuthConnectV6] {
        let mut luids: Vec<u64> = foreign_luids
            .iter()
            .copied()
            .filter(|l| *l != 0 && *l != own)
            .filter(|l| {
                emitted.iter().any(|f| {
                    f.layer == layer
                        && f.action == WfpAction::Permit
                        && f.local_interface_luid == Some(*l)
                        && f.user_sid.as_deref().is_none_or(|s| s == sid)
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
                veto.id = filter_id_for(
                    sid,
                    KILLSWITCH_ROLE,
                    &permit_luid_seg(luid),
                    "ks-doh-foreign",
                    &format!("{:016x}", block.id.raw),
                );
                out.push(veto);
            }
        }
    }
    out
}

/// Exemption permit for a remote subnet (loopback / link-local / LAN).
/// `pub(super)` because the emitters moved out of `killswitch_codegen` and it
/// is now the caller.
pub(super) fn exempt_subnet(
    sid: &str,
    net: Ipv4Addr,
    prefix_len: u8,
    weight: u64,
) -> WfpFilterSpec {
    let target = format!("{net}/{prefix_len}");
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Permit,
        remote_ip: None,
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight,
        id: filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-ca-subnet", &target),
        user_sid: Some(sid.to_string()),
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: Some((net, prefix_len)),
        remote_subnet_v6: None,
        ip_protocol: None,
        remote_subnet_set: Vec::new(),
    }
}

/// Exemption permit for an exact remote host (VPN server / broadcast).
/// `pub(super)` because the emitters moved out of `killswitch_codegen` and it
/// is now the caller.
pub(super) fn exempt_host(sid: &str, ip: Ipv4Addr, weight: u64) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Permit,
        remote_ip: Some(ip),
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight,
        id: filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-ca-host", &ip.to_string()),
        user_sid: Some(sid.to_string()),
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
        remote_subnet_set: Vec::new(),
    }
}

/// ALE exempt for a KNOWN-DIRECT destination under the
/// catch-all block-all (see [`FailClosedExemptions::known_direct_ips`]).
/// Distinct id kind from [`exempt_host`] so an IP that is also a bootstrap
/// VPN server does not collide filter ids in one desired set.
/// `pub(super)` because the emitters moved out of `killswitch_codegen` and it
/// is now the caller.
pub(super) fn exempt_direct_host(sid: &str, ip: Ipv4Addr, weight: u64) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Permit,
        remote_ip: Some(ip),
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight,
        id: filter_id_for(
            sid,
            KILLSWITCH_ROLE,
            "",
            "ks-ca-direct-host",
            &ip.to_string(),
        ),
        user_sid: Some(sid.to_string()),
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
        remote_subnet_set: Vec::new(),
    }
}

/// ALE exempt for a liveness-probe target (the secondary tunnel's next-hop) —
/// see [`FailClosedExemptions::probe_target_ips`]. Distinct id kind from
/// [`exempt_host`] / [`exempt_direct_host`] so overlapping IPs keep distinct
/// filter ids in one desired set.
/// `pub(super)` because the emitters moved out of `killswitch_codegen` and it
/// is now the caller.
pub(super) fn exempt_probe_target(sid: &str, ip: Ipv4Addr, weight: u64) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Permit,
        remote_ip: Some(ip),
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight,
        id: filter_id_for(
            sid,
            KILLSWITCH_ROLE,
            "",
            "ks-ca-probe-host",
            &ip.to_string(),
        ),
        user_sid: Some(sid.to_string()),
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
        remote_subnet_set: Vec::new(),
    }
}

/// Most resolvers the DNS permit names; the OS lists two or three.
pub const MAX_DNS_SERVER_PERMITS: usize = 8;

/// Port-scoped permits for outbound DNS (remote port 53, UDP + TCP) at the ALE
/// connect layer, one pair per system resolver, so name resolution keeps
/// working over the PRIMARY link while the catch-all block-all is engaged.
/// Opt-in only (see [`FailClosedExemptions::allow_dns_over_primary`]) and
/// pinned to the machine's own resolvers: port 53 to any host is a tunnel for
/// every program that runs its own DNS. No servers, no permits.
pub(super) fn exempt_dns_over_primary(
    sid: &str,
    servers: &[IpAddr],
    base_weight: u64,
) -> Vec<WfpFilterSpec> {
    const IP_PROTO_UDP: u8 = 17;
    const IP_PROTO_TCP: u8 = 6;
    let capped: Vec<IpAddr> = servers
        .iter()
        .copied()
        .filter(|ip| !is_exempt_from_blocking(*ip))
        .take(MAX_DNS_SERVER_PERMITS)
        .collect();
    capped
        .iter()
        .flat_map(|ip| {
            [(IP_PROTO_UDP, "udp53"), (IP_PROTO_TCP, "tcp53")]
                .into_iter()
                .map(move |(proto, tag)| (*ip, proto, tag))
        })
        .enumerate()
        .map(|(i, (ip, proto, tag))| {
            let (layer, kind, remote_ip, remote_subnet_v6) = match ip {
                IpAddr::V4(v4) => (WfpLayerKey::AleAuthConnectV4, "ks-ca-dns", Some(v4), None),
                IpAddr::V6(v6) => (
                    WfpLayerKey::AleAuthConnectV6,
                    "ks-ca-dns-v6",
                    None,
                    Some((v6, 128)),
                ),
            };
            WfpFilterSpec {
                layer,
                action: WfpAction::Permit,
                remote_ip,
                remote_ip_set: Vec::new(),
                remote_ip_set_v6: Vec::new(),
                remote_port: Some(53),
                weight: base_weight + i as u64,
                id: filter_id_for(sid, KILLSWITCH_ROLE, &ip.to_string(), kind, tag),
                user_sid: Some(sid.to_string()),
                app_pattern: None,
                local_interface_luid: None,
                remote_subnet: None,
                remote_subnet_v6,
                ip_protocol: Some(proto),
                remote_subnet_set: Vec::new(),
            }
        })
        .collect()
}
