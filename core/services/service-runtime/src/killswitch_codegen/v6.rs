//! The IPv6 half of the catch-all cut.
//!
//! Separate from the v4 emitter because the two are not symmetric and the
//! asymmetry is the point: the v6 ALE layer exposes `ALE_USER_ID`, so those
//! filters are scoped to a SID, while the v6 transport layer has no ALE id at
//! all and carries `user_sid = None`. Reading that next to the v4 code invited
//! copying one into the other.
//!
//! What the block must never cut is the same list as on the v4 side — the
//! link's own upkeep, the tunnel's endpoints, the LAN — read off the route
//! table rather than guessed.

use std::net::Ipv6Addr;

use nrr_platform_api::types::{WfpAction, WfpFilterSpec, WfpLayerKey};

use super::{
    permit_luid_seg, KillSwitchProtocols, CATCHALL_BLOCK_WEIGHT, CATCHALL_EXEMPT_BASE,
    KILLSWITCH_ROLE, PACKET_BLOCK_BASE,
};
use crate::wfp_bands::PACKET_V6_EXEMPT_BASE;
use crate::wfp_codegen::filter_id_for;

const ALE: WfpLayerKey = WfpLayerKey::AleAuthConnectV6;
const TRANSPORT: WfpLayerKey = WfpLayerKey::OutboundTransportV6;

/// IPv6 loopback `::1/128` — exempt (local IPC / stub resolvers over v6).
const V6_LOOPBACK: Ipv6Addr = Ipv6Addr::LOCALHOST;
/// IPv6 link-local base `fe80::` (paired with `/10`) — exempt (the unicast
/// half of SLAAC/NDP).
const V6_LINK_LOCAL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0);
/// IPv6 link-local MULTICAST base `ff02::` (paired with `/16`) — exempt.
/// Neighbour discovery, duplicate-address detection, MLD, mDNS, LLMNR and
/// DHCPv6 all address the GROUP, not `fe80::`, so the unicast exemption above
/// never covered them: cutting this scope breaks the link's own upkeep while
/// leaking nothing — link-local multicast cannot cross a router.
const V6_LINK_LOCAL_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0);

/// Emit the IPv6 half of a catch-all block: the link-scope exemptions, the
/// tunnel's own `/128` endpoints and the primary link's attached prefixes,
/// over the user's block-all at the V6 ALE layer and, below it, a block per
/// selected non-TCP/UDP protocol (ICMPv6, GRE, ESP) at the V6 transport layer
/// — the shape of the v4 half.
///
/// A protocol-less block below ALE would cut the system's IKE too, and no
/// user condition there could spare it: a VPN whose server is IPv6 never
/// connected, and its drop named no user, so nobody could be asked about the
/// gateway. TCP/UDP is cut only where the drop names its user.
///
/// `server_ips` and `local_subnets` are the v6 twins of what the v4 half
/// exempts. Without the servers, a tunnel whose endpoint is reachable only over
/// IPv6 could never dial out from under its own guard; without the subnets, the
/// v6 LAN — the printer, the NAS, the router's own management address — dies
/// with the tunnel it never used.
///
/// The transport layer cannot be scoped to a user either. With
/// `machine_has_other_principals` its half is left out and the per-SID ALE
/// filters carry the cut alone, so the other users' networking stays whole.
pub fn catch_all_v6_filters(
    sid: &str,
    secondary_luid: u64,
    server_ips: &[Ipv6Addr],
    local_subnets: &[(Ipv6Addr, u8)],
    protocols: KillSwitchProtocols,
    machine_has_other_principals: bool,
) -> Vec<WfpFilterSpec> {
    let below_ale = if machine_has_other_principals {
        Vec::new()
    } else {
        protocols.packet_named_v6()
    };
    let transport = !below_ale.is_empty();
    let mut out = Vec::new();
    // Anything leaving through the tunnel survives the cut: a tunnel whose
    // endpoint is a v6 address must be able to reconnect. `0` means the tunnel
    // is unresolved and there is no egress to permit.
    if secondary_luid != 0 {
        out.push(egress_permit_v6(sid, ALE, secondary_luid));
        if transport {
            out.push(egress_permit_v6(sid, TRANSPORT, secondary_luid));
        }
    }
    let link_scope = [
        (V6_LOOPBACK, 128u8),
        (V6_LINK_LOCAL, 10),
        (V6_LINK_LOCAL_MULTICAST, 16),
    ];
    for (e, (net, prefix)) in link_scope.iter().enumerate() {
        out.push(exempt_subnet_v6(
            sid,
            ALE,
            *net,
            *prefix,
            CATCHALL_EXEMPT_BASE + e as u64,
        ));
    }
    out.push(block_all_v6(sid));
    if transport {
        for (e, (net, prefix)) in link_scope.iter().enumerate() {
            out.push(exempt_subnet_v6(
                sid,
                TRANSPORT,
                *net,
                *prefix,
                PACKET_V6_EXEMPT_BASE + e as u64,
            ));
        }
        for (k, proto) in below_ale.into_iter().enumerate() {
            out.push(block_protocol_v6(sid, proto, k as u64));
        }
    }
    // The address-scoped exemptions continue the band after the three
    // link-scope ones above, at both layers.
    let scoped = server_ips
        .iter()
        .map(|ip| (*ip, 128u8))
        .chain(local_subnets.iter().copied());
    for (e, (net, prefix)) in scoped.enumerate() {
        let e = e as u64;
        out.push(exempt_subnet_v6(
            sid,
            ALE,
            net,
            prefix,
            CATCHALL_EXEMPT_BASE + 3 + e,
        ));
        if transport {
            out.push(exempt_subnet_v6(
                sid,
                TRANSPORT,
                net,
                prefix,
                PACKET_V6_EXEMPT_BASE + 3 + e,
            ));
        }
    }
    out
}

/// The v6 twin of `destination_less_floor`: ALE only, the layer the per-app
/// blocks sit at. Same ids and weights as [`catch_all_v6_filters`]' ALE half.
pub fn destination_less_floor_v6(
    sid: &str,
    server_ips: &[Ipv6Addr],
    local_subnets: &[(Ipv6Addr, u8)],
) -> Vec<WfpFilterSpec> {
    let link_scope = [
        (V6_LOOPBACK, 128u8),
        (V6_LINK_LOCAL, 10),
        (V6_LINK_LOCAL_MULTICAST, 16),
    ];
    link_scope
        .into_iter()
        .chain(server_ips.iter().map(|ip| (*ip, 128u8)))
        .chain(local_subnets.iter().copied())
        .enumerate()
        .map(|(e, (net, prefix))| {
            exempt_subnet_v6(sid, ALE, net, prefix, CATCHALL_EXEMPT_BASE + e as u64)
        })
        .collect()
}

/// Permit for traffic egressing the tunnel, on a v6 layer.
fn egress_permit_v6(sid: &str, layer: WfpLayerKey, secondary_luid: u64) -> WfpFilterSpec {
    let below_ale = layer == TRANSPORT;
    WfpFilterSpec {
        layer,
        action: WfpAction::Permit,
        remote_ip: None,
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        // Above the exemption band so it outranks every block on this layer.
        weight: CATCHALL_EXEMPT_BASE + 100,
        id: filter_id_for(
            sid,
            KILLSWITCH_ROLE,
            &permit_luid_seg(secondary_luid),
            if below_ale {
                "ks-ca-egress-v6-tr"
            } else {
                "ks-ca-egress-v6-ale"
            },
            "secondary",
        ),
        // The transport layer carries no ALE_USER_ID condition, so a v6 permit
        // there is machine-wide - as are the blocks it outranks.
        user_sid: if below_ale {
            None
        } else {
            Some(sid.to_string())
        },
        app_pattern: None,
        local_interface_luid: Some(secondary_luid),
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
        remote_subnet_set: Vec::new(),
    }
}

/// IPv6 exemption permit for a remote subnet (loopback / link-local) at the
/// given V6 layer. Transport-layer filters carry `user_sid = None`.
fn exempt_subnet_v6(
    sid: &str,
    layer: WfpLayerKey,
    net: Ipv6Addr,
    prefix_len: u8,
    weight: u64,
) -> WfpFilterSpec {
    let below_ale = layer == TRANSPORT;
    // The filter id seed excludes the layer, so the ALE and transport twins
    // MUST use distinct kind tags or their UUIDs collide (add-only install
    // would swallow one as a duplicate).
    let kind = if below_ale {
        "ks-ca-subnet-v6-tr"
    } else {
        "ks-ca-subnet-v6-ale"
    };
    WfpFilterSpec {
        layer,
        action: WfpAction::Permit,
        remote_ip: None,
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight,
        id: filter_id_for(
            sid,
            KILLSWITCH_ROLE,
            "",
            kind,
            &format!("{net}/{prefix_len}"),
        ),
        user_sid: if below_ale {
            None
        } else {
            Some(sid.to_string())
        },
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: Some((net, prefix_len)),
        ip_protocol: None,
        remote_subnet_set: Vec::new(),
    }
}

/// The user's IPv6 block-all at the V6 ALE layer: TCP/UDP off the tunnel,
/// scoped to `sid`, so its drop names the user it was for.
fn block_all_v6(sid: &str) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: ALE,
        action: WfpAction::Block,
        remote_ip: None,
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight: CATCHALL_BLOCK_WEIGHT,
        id: filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-ca-block-v6-ale", "block-all"),
        user_sid: Some(sid.to_string()),
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
        remote_subnet_set: Vec::new(),
    }
}

/// One non-TCP/UDP protocol off the tunnel, at the V6 transport layer — the
/// v6 twin of the v4 per-protocol block. Machine-wide: no user id there.
fn block_protocol_v6(sid: &str, proto: u8, k: u64) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: TRANSPORT,
        action: WfpAction::Block,
        remote_ip: None,
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight: PACKET_BLOCK_BASE + k,
        id: filter_id_for(
            sid,
            KILLSWITCH_ROLE,
            "",
            "ks-ca-block-v6-tr",
            &format!("proto-{proto}"),
        ),
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: Some(proto),
        remote_subnet_set: Vec::new(),
    }
}
