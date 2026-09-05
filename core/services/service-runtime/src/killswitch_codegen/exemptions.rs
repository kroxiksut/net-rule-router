//! One ordered emitter for everything the cut must not take with it.
//!
//! Loopback, the link's own upkeep, DHCP, the local subnets, the addresses a
//! tunnel needs to come back up — plus the per-shape permits the callers emit
//! them with. They were scattered between the three block emitters, and the
//! failure mode of that arrangement is specific: turning the kill switch OFF
//! used to leave a bare block-all with no exemptions at all, because the
//! exemptions lived inside the guarded branch and the block did not.
//!
//! Behaviour is unchanged: the same functions, verbatim.

use std::net::Ipv4Addr;

use nrr_platform_api::types::{WfpAction, WfpFilterSpec, WfpLayerKey};

use super::*;

/// The exemptions that must accompany the Strict-mode default block when the
/// leak-guard is OFF.
///
/// The default block is part of the MODE (everything not named by a rule is
/// dropped), not part of the guard, so it is emitted whenever the mode is
/// Strict. Its exemptions, though, were emitted only inside the guard's own
/// branch: turning the kill-switch off left a bare block-all scoped to the SID
/// with no loopback, no LAN, no DHCP and no way to reach the VPN server - the
/// user asked to stop protecting against leaks and got their machine cut off
/// instead.
#[must_use]
pub fn default_block_exemptions(
    sid: &str,
    exemptions: &FailClosedExemptions,
) -> Vec<WfpFilterSpec> {
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
    }
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
        remote_port: None,
        weight,
        id: filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-ca-subnet", &target),
        user_sid: Some(sid.to_string()),
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: Some((net, prefix_len)),
        remote_subnet_v6: None,
        ip_protocol: None,
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
        remote_port: None,
        weight,
        id: filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-ca-host", &ip.to_string()),
        user_sid: Some(sid.to_string()),
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
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
    }
}

/// port-scoped exemption permits for outbound DNS (remote port
/// 53, UDP + TCP) at the ALE connect layer, so name resolution keeps working over
/// the PRIMARY link while the catch-all block-all is engaged. Opt-in only (see
/// [`FailClosedExemptions::allow_dns_over_primary`]); narrowed to port 53 so it is
/// not a full-host tunnel. Returns two specs (UDP then TCP).
/// `pub(super)` because the emitters moved out of `killswitch_codegen` and it
/// is now the caller.
pub(super) fn exempt_dns_over_primary(sid: &str, base_weight: u64) -> Vec<WfpFilterSpec> {
    const IP_PROTO_UDP: u8 = 17;
    const IP_PROTO_TCP: u8 = 6;
    [(IP_PROTO_UDP, "udp53"), (IP_PROTO_TCP, "tcp53")]
        .into_iter()
        .enumerate()
        .map(|(i, (proto, tag))| WfpFilterSpec {
            layer: WfpLayerKey::AleAuthConnectV4,
            action: WfpAction::Permit,
            remote_ip: None,
            remote_ip_set: Vec::new(),
            remote_port: Some(53),
            weight: base_weight + i as u64,
            id: filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-ca-dns", tag),
            user_sid: Some(sid.to_string()),
            app_pattern: None,
            local_interface_luid: None,
            remote_subnet: None,
            remote_subnet_v6: None,
            ip_protocol: Some(proto),
        })
        .collect()
}
