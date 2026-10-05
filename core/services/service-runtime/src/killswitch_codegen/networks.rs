//! The kill-switch over the additional link's networks.
//!
//! Each held network gets one filter set, never one per address; each cut-out
//! one permit. The windows are declared in `wfp_bands`, past the per-address
//! pin windows, so a network never shares a slot with a pin:
//!
//! | Filter | Layer | Weight |
//! |--------|-------|--------|
//! | hold block | ALE | `KILLSWITCH_NETWORK_BLOCK_BASE + i` |
//! | hold egress permit | ALE | `KILLSWITCH_NETWORK_PERMIT_BASE + i` |
//! | cut-out permit | ALE | `NETWORK_CUT_OUT_BASE + j` |
//! | hold block | transport | `PACKET_NETWORK_BLOCK_BASE + 16 * i + k` |
//! | hold egress permit | transport | `PACKET_NETWORK_PERMIT_BASE + 16 * i + k` |
//! | cut-out permit | transport | `PACKET_NETWORK_CUT_OUT_BASE + j` |

use nrr_shared::ip_block::IpBlock;

use crate::enforcement_planner::{never_blocked_networks, NetworkHolds};
use crate::wfp_bands::{
    KILLSWITCH_NETWORK_BLOCK_BASE, KILLSWITCH_NETWORK_PERMIT_BASE, NETWORK_CUT_OUT_BASE,
    PACKET_NETWORK_BLOCK_BASE, PACKET_NETWORK_CUT_OUT_BASE, PACKET_NETWORK_PERMIT_BASE,
    PACKET_SLOTS_PER_DESTINATION,
};

use super::*;

impl FailClosedExemptions {
    /// What a held network must leave open on this machine.
    #[must_use]
    pub fn never_blocked_networks(&self) -> Vec<IpBlock> {
        never_blocked_networks(
            self.bootstrap_server_ips
                .iter()
                .chain(&self.probe_target_ips)
                .map(|ip| IpAddr::V4(*ip))
                .chain(
                    self.bootstrap_server_ips_v6
                        .iter()
                        .map(|ip| IpAddr::V6(*ip)),
                ),
            self.local_subnets
                .iter()
                .map(|(net, len)| (IpAddr::V4(*net), *len))
                .chain(
                    self.local_subnets_v6
                        .iter()
                        .map(|(net, len)| (IpAddr::V6(*net), *len)),
                ),
        )
    }
}

impl KillSwitchResolution {
    /// What a held network must leave open on this machine.
    #[must_use]
    pub fn never_blocked_networks(&self) -> Vec<IpBlock> {
        never_blocked_networks(
            self.bootstrap_server_ips
                .iter()
                .map(|ip| IpAddr::V4(*ip))
                .chain(
                    self.bootstrap_server_ips_v6
                        .iter()
                        .map(|ip| IpAddr::V6(*ip)),
                ),
            self.local_subnets
                .iter()
                .map(|(net, len)| (IpAddr::V4(*net), *len))
                .chain(
                    self.local_subnets_v6
                        .iter()
                        .map(|(net, len)| (IpAddr::V6(*net), *len)),
                ),
        )
    }
}

/// The leak-proof pair over each held network while the tunnel is resolvable:
/// permitted while egressing `secondary_luid`, blocked the instant it does not.
/// Fails open on a zero LUID, like [`kill_switch_filters`].
#[must_use]
pub fn kill_switch_network_filters(
    sid: &str,
    holds: &NetworkHolds,
    secondary_luid: u64,
    protocols: KillSwitchProtocols,
) -> Vec<WfpFilterSpec> {
    if secondary_luid == 0 {
        return Vec::new();
    }
    let luid_seg = permit_luid_seg(secondary_luid);
    let mut out = Vec::new();
    for (i, net) in holds.held.iter().copied().enumerate() {
        let i = i as u64;
        if protocols.wants_ale_block() {
            let mut permit = net_spec(
                net,
                ale_layer_of(net),
                WfpAction::Permit,
                KILLSWITCH_NETWORK_PERMIT_BASE + i,
                filter_id_for(
                    sid,
                    KILLSWITCH_ROLE,
                    &luid_seg,
                    "ks-net-permit",
                    &net.to_string(),
                ),
            );
            permit.user_sid = Some(sid.to_string());
            permit.local_interface_luid = Some(secondary_luid);
            out.push(permit);
            let mut block = net_spec(
                net,
                ale_layer_of(net),
                WfpAction::Block,
                KILLSWITCH_NETWORK_BLOCK_BASE + i,
                filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-net-block", &net.to_string()),
            );
            block.user_sid = Some(sid.to_string());
            out.push(block);
        }
        // IPv4 only, for the reason the per-address pin gives: the v6 transport
        // layer is not modelled, and a held network's own traffic is TCP/UDP.
        if net.is_ipv4() {
            for (k, proto) in protocols.packet_named().into_iter().enumerate() {
                let slot = i * PACKET_SLOTS_PER_DESTINATION + k as u64;
                let mut permit = net_spec(
                    net,
                    WfpLayerKey::OutboundTransportV4,
                    WfpAction::Permit,
                    PACKET_NETWORK_PERMIT_BASE + slot,
                    filter_id_for(
                        sid,
                        KILLSWITCH_ROLE,
                        &luid_seg,
                        "ks-tr-net-egress",
                        &format!("{net}-{proto}"),
                    ),
                );
                permit.local_interface_luid = Some(secondary_luid);
                permit.ip_protocol = Some(proto);
                out.push(permit);
                out.push(transport_hold_block(sid, net, proto, slot));
            }
        }
    }
    out.extend(cut_out_filters(sid, holds, protocols));
    out
}

/// The held networks blocked outright while the tunnel cannot be resolved,
/// narrowed to `protocols` like [`fail_closed_block_destinations`].
#[must_use]
pub fn fail_closed_network_filters(
    sid: &str,
    holds: &NetworkHolds,
    protocols: KillSwitchProtocols,
) -> Vec<WfpFilterSpec> {
    if !protocols.any() {
        return Vec::new();
    }
    let ale_protocol = protocols.ale_protocol();
    let mut out = Vec::new();
    for (i, net) in holds.held.iter().copied().enumerate() {
        let i = i as u64;
        if protocols.wants_ale_block() {
            let tag = format!(
                "{net}-{}",
                ale_protocol.map_or("any".to_string(), |p| p.to_string())
            );
            let mut block = net_spec(
                net,
                ale_layer_of(net),
                WfpAction::Block,
                KILLSWITCH_NETWORK_BLOCK_BASE + i,
                filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-net-fc-block", &tag),
            );
            block.user_sid = Some(sid.to_string());
            block.ip_protocol = ale_protocol;
            out.push(block);
        }
        if net.is_ipv4() {
            for (k, proto) in protocols.packet_named().into_iter().enumerate() {
                let slot = i * PACKET_SLOTS_PER_DESTINATION + k as u64;
                out.push(transport_hold_block(sid, net, proto, slot));
            }
        }
    }
    out.extend(cut_out_filters(sid, holds, protocols));
    out
}

/// One unconditional permit per cut-out at each layer a hold blocks on.
fn cut_out_filters(
    sid: &str,
    holds: &NetworkHolds,
    protocols: KillSwitchProtocols,
) -> Vec<WfpFilterSpec> {
    let mut out = Vec::new();
    for (j, cut) in holds.cut_outs.iter().copied().enumerate() {
        let j = j as u64;
        if protocols.wants_ale_block() {
            let mut permit = net_spec(
                cut,
                ale_layer_of(cut),
                WfpAction::Permit,
                NETWORK_CUT_OUT_BASE + j,
                filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-net-cut", &cut.to_string()),
            );
            permit.user_sid = Some(sid.to_string());
            out.push(permit);
        }
        if cut.is_ipv4() && protocols.wants_packet_layer() {
            out.push(net_spec(
                cut,
                WfpLayerKey::OutboundTransportV4,
                WfpAction::Permit,
                PACKET_NETWORK_CUT_OUT_BASE + j,
                filter_id_for(sid, KILLSWITCH_ROLE, "", "ks-tr-net-cut", &cut.to_string()),
            ));
        }
    }
    out
}

/// The transport-layer block both postures share, so the same network keeps
/// one id across a tunnel drop.
fn transport_hold_block(sid: &str, net: IpBlock, proto: u8, slot: u64) -> WfpFilterSpec {
    let mut block = net_spec(
        net,
        WfpLayerKey::OutboundTransportV4,
        WfpAction::Block,
        PACKET_NETWORK_BLOCK_BASE + slot,
        filter_id_for(
            sid,
            KILLSWITCH_ROLE,
            "",
            "ks-tr-net-block",
            &format!("{net}-{proto}"),
        ),
    );
    block.ip_protocol = Some(proto);
    block
}

fn ale_layer_of(block: IpBlock) -> WfpLayerKey {
    if block.is_ipv4() {
        WfpLayerKey::AleAuthConnectV4
    } else {
        WfpLayerKey::AleAuthConnectV6
    }
}

/// A filter over one block, scoped to nobody; callers add the SID at ALE (the
/// layers below it carry no user id).
fn net_spec(
    block: IpBlock,
    layer: WfpLayerKey,
    action: WfpAction,
    weight: u64,
    id: nrr_platform_api::types::WfpFilterId,
) -> WfpFilterSpec {
    let (remote_ip, remote_subnet, remote_subnet_v6) = match block.network() {
        IpAddr::V4(net) if block.is_single_address() => (Some(net), None, None),
        IpAddr::V4(net) => (None, Some((net, block.prefix_len())), None),
        IpAddr::V6(net) => (None, None, Some((net, block.prefix_len()))),
    };
    WfpFilterSpec {
        layer,
        action,
        remote_ip,
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight,
        id,
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet,
        remote_subnet_v6,
        ip_protocol: None,
    }
}
