//! The IPv6 half of the catch-all cut.
//!
//! Separate from the v4 emitter because the two are not symmetric and the
//! asymmetry is the point: the v6 ALE layer exposes `ALE_USER_ID`, so those
//! filters are scoped to a SID, while the v6 packet layer has no ALE id at all
//! and carries `user_sid = None`. Reading that next to the v4 code invited
//! copying one into the other.
//!
//! Behaviour is unchanged: the same functions, verbatim.

use std::net::Ipv6Addr;

use nrr_platform_api::types::{WfpAction, WfpFilterSpec, WfpLayerKey};

use super::{
    permit_luid_seg, CATCHALL_BLOCK_WEIGHT, CATCHALL_EXEMPT_BASE, KILLSWITCH_ROLE,
    PACKET_BLOCK_BASE, PACKET_EXEMPT_BASE,
};
use crate::wfp_codegen::filter_id_for;

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

/// Emit the IPv6 half of a catch-all block: loopback + link-local +
/// link-local-multicast exemption permits over an unconditional block-all, at
/// BOTH the V6 ALE-connect and V6
/// packet layers. ALE-layer filters are scoped to `sid` (the V6 ALE layer
/// exposes `ALE_USER_ID`); packet-layer filters carry `user_sid = None` (no ALE
/// id there — the same caveat as the V4 packet layer). Distinct id seeds per
/// (layer, target) so every filter gets a unique UUID.
pub fn catch_all_v6_filters(sid: &str, secondary_luid: u64) -> Vec<WfpFilterSpec> {
    let mut out = Vec::new();
    // Anything leaving through the tunnel survives the cut. Without this the v6
    // block-all was absolute, and a tunnel whose endpoint is a v6 address could
    // not reconnect from any user - the deadlock the v4 half is careful to
    // avoid via the server exemption. `0` means the tunnel is unresolved and
    // there is no egress to permit.
    if secondary_luid != 0 {
        for layer in [
            WfpLayerKey::AleAuthConnectV6,
            WfpLayerKey::OutboundIpPacketV6,
        ] {
            out.push(egress_permit_v6(sid, layer, secondary_luid));
        }
    }
    out.extend([
        // ── V6 ALE connect layer (TCP/UDP over IPv6) ──
        exempt_subnet_v6(
            sid,
            WfpLayerKey::AleAuthConnectV6,
            V6_LOOPBACK,
            128,
            CATCHALL_EXEMPT_BASE,
        ),
        exempt_subnet_v6(
            sid,
            WfpLayerKey::AleAuthConnectV6,
            V6_LINK_LOCAL,
            10,
            CATCHALL_EXEMPT_BASE + 1,
        ),
        exempt_subnet_v6(
            sid,
            WfpLayerKey::AleAuthConnectV6,
            V6_LINK_LOCAL_MULTICAST,
            16,
            CATCHALL_EXEMPT_BASE + 2,
        ),
        block_all_v6(sid, WfpLayerKey::AleAuthConnectV6),
        // ── V6 packet layer (ICMPv6 / everything else) ──
        exempt_subnet_v6(
            sid,
            WfpLayerKey::OutboundIpPacketV6,
            V6_LOOPBACK,
            128,
            PACKET_EXEMPT_BASE,
        ),
        exempt_subnet_v6(
            sid,
            WfpLayerKey::OutboundIpPacketV6,
            V6_LINK_LOCAL,
            10,
            PACKET_EXEMPT_BASE + 1,
        ),
        exempt_subnet_v6(
            sid,
            WfpLayerKey::OutboundIpPacketV6,
            V6_LINK_LOCAL_MULTICAST,
            16,
            PACKET_EXEMPT_BASE + 2,
        ),
        block_all_v6(sid, WfpLayerKey::OutboundIpPacketV6),
    ]);
    out
}

/// Permit for traffic egressing the tunnel, on a v6 layer.
fn egress_permit_v6(sid: &str, layer: WfpLayerKey, secondary_luid: u64) -> WfpFilterSpec {
    let is_packet = matches!(layer, WfpLayerKey::OutboundIpPacketV6);
    WfpFilterSpec {
        layer,
        action: WfpAction::Permit,
        remote_ip: None,
        remote_ip_set: Vec::new(),
        remote_port: None,
        // Above the exemption band so it outranks every block on this layer.
        weight: CATCHALL_EXEMPT_BASE + 100,
        id: filter_id_for(
            sid,
            KILLSWITCH_ROLE,
            &permit_luid_seg(secondary_luid),
            if is_packet {
                "ks-ca-egress-v6-pkt"
            } else {
                "ks-ca-egress-v6-ale"
            },
            "secondary",
        ),
        // The packet layer carries no ALE_USER_ID condition, so a v6 permit
        // there is machine-wide - as is the block it outranks.
        user_sid: if is_packet {
            None
        } else {
            Some(sid.to_string())
        },
        app_pattern: None,
        local_interface_luid: Some(secondary_luid),
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

/// IPv6 exemption permit for a remote subnet (loopback / link-local) at the
/// given V6 layer. Packet-layer filters carry `user_sid = None`.
fn exempt_subnet_v6(
    sid: &str,
    layer: WfpLayerKey,
    net: Ipv6Addr,
    prefix_len: u8,
    weight: u64,
) -> WfpFilterSpec {
    let is_packet = matches!(layer, WfpLayerKey::OutboundIpPacketV6);
    // The filter id seed excludes the layer, so the ALE and packet twins MUST
    // use distinct kind tags or their UUIDs collide (add-only install would
    // swallow one as a duplicate).
    let kind = if is_packet {
        "ks-ca-subnet-v6-pkt"
    } else {
        "ks-ca-subnet-v6-ale"
    };
    WfpFilterSpec {
        layer,
        action: WfpAction::Permit,
        remote_ip: None,
        remote_ip_set: Vec::new(),
        remote_port: None,
        weight,
        id: filter_id_for(
            sid,
            KILLSWITCH_ROLE,
            "",
            kind,
            &format!("{net}/{prefix_len}"),
        ),
        user_sid: if is_packet {
            None
        } else {
            Some(sid.to_string())
        },
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: Some((net, prefix_len)),
        ip_protocol: None,
    }
}

/// IPv6 catch-all block-all (no conditions) at the given V6 layer. Its weight
/// mirrors the V4 block band for that layer. Packet-layer filters carry
/// `user_sid = None`.
fn block_all_v6(sid: &str, layer: WfpLayerKey) -> WfpFilterSpec {
    let is_packet = matches!(layer, WfpLayerKey::OutboundIpPacketV6);
    let (weight, kind) = if is_packet {
        (PACKET_BLOCK_BASE, "ks-ca-block-v6-pkt")
    } else {
        (CATCHALL_BLOCK_WEIGHT, "ks-ca-block-v6-ale")
    };
    WfpFilterSpec {
        layer,
        action: WfpAction::Block,
        remote_ip: None,
        remote_ip_set: Vec::new(),
        remote_port: None,
        weight,
        id: filter_id_for(sid, KILLSWITCH_ROLE, "", kind, "block-all"),
        user_sid: if is_packet {
            None
        } else {
            Some(sid.to_string())
        },
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}
