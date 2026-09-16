use super::*;

// ── Protocol-aware filter builders (multi-protocol kill-switch) ──────────────

/// Destination scope of a kill-switch filter: everything (the catch-all
/// forms) or one packed chunk of destinations. The single-address form is
/// gone deliberately — per-address filters are what grew the standing set
/// into the thousands.
#[derive(Clone, Copy)]
pub(super) enum DestScope<'a> {
    All,
    Chunk(&'a V4SlotChunk),
}

impl DestScope<'_> {
    fn members(self) -> Vec<Ipv4Addr> {
        match self {
            DestScope::All => Vec::new(),
            DestScope::Chunk(c) => c.members.clone(),
        }
    }

    fn key(self) -> String {
        match self {
            DestScope::All => "all".into(),
            DestScope::Chunk(c) => c.id_seg(),
        }
    }
}

/// Build a scope/protocol key for a packet- or ALE-layer filter id.
/// [`DestScope::All`] → "all"; `proto = None` → "any".
fn proto_scope_key(scope: DestScope<'_>, proto: Option<u8>) -> String {
    let p = proto.map(|p| p.to_string()).unwrap_or_else(|| "any".into());
    format!("{}-{p}", scope.key())
}

/// ALE-layer block, optionally narrowed to one IP protocol (TCP/UDP). Scoped
/// to `sid` (ALE exposes `ALE_USER_ID`). [`DestScope::All`] blocks all
/// destinations.
pub(super) fn ale_block(
    sid: &str,
    scope: DestScope<'_>,
    proto: Option<u8>,
    weight: u64,
) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip: None,
        remote_ip_set: scope.members(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight,
        id: filter_id_for(
            sid,
            KILLSWITCH_ROLE,
            "",
            "ks-ale-block",
            &proto_scope_key(scope, proto),
        ),
        user_sid: Some(sid.to_string()),
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: proto,
    }
}

/// Below-ALE block at `layer`. ⚠ Neither the packet layer nor the transport
/// layer exposes `ALE_USER_ID`, so `user_sid` MUST be `None` (system-wide);
/// the id is still seeded with `sid` for uniqueness + cleanup tracking.
///
/// a protocol-narrowed block (`proto = Some`) MUST target
/// [`WfpLayerKey::OutboundTransportV4`] — the IPPACKET layers have no
/// `FWPM_CONDITION_IP_PROTOCOL` and `FwpmFilterAdd0` rejects the filter with
/// `FWP_E_CONDITION_NOT_FOUND` (every named-protocol kill-switch block
/// silently failed to install from  until this fix). The kind tag
/// is layer-specific so a transport filter never collides UUIDs with a
/// historically-installed packet-layer twin.
fn packet_block(
    sid: &str,
    layer: WfpLayerKey,
    scope: DestScope<'_>,
    proto: Option<u8>,
    weight: u64,
) -> WfpFilterSpec {
    let kind = if layer == WfpLayerKey::OutboundTransportV4 {
        "ks-tr-block"
    } else {
        "ks-pkt-block"
    };
    WfpFilterSpec {
        layer,
        action: WfpAction::Block,
        remote_ip: None,
        remote_ip_set: scope.members(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight,
        id: filter_id_for(
            sid,
            KILLSWITCH_ROLE,
            "",
            kind,
            &proto_scope_key(scope, proto),
        ),
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: proto,
    }
}

/// Below-ALE exemption permit for a remote subnet (loopback / link-local /
/// LAN) at `layer`. Protocol-agnostic. `user_sid = None` (no ALE ids below
/// the ALE layers). Layer-specific kind tag — see [`packet_block`].
pub(super) fn packet_exempt_subnet(
    sid: &str,
    layer: WfpLayerKey,
    net: Ipv4Addr,
    prefix_len: u8,
    weight: u64,
) -> WfpFilterSpec {
    let kind = if layer == WfpLayerKey::OutboundTransportV4 {
        "ks-tr-exempt-net"
    } else {
        "ks-pkt-exempt-net"
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
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: Some((net, prefix_len)),
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

/// Below-ALE exemption permit for an exact remote host (VPN server /
/// broadcast) at `layer`. Protocol-agnostic. `user_sid = None` (no ALE ids
/// below the ALE layers). Layer-specific kind tag — see [`packet_block`].
pub(super) fn packet_exempt_host(
    sid: &str,
    layer: WfpLayerKey,
    ip: Ipv4Addr,
    weight: u64,
) -> WfpFilterSpec {
    let kind = if layer == WfpLayerKey::OutboundTransportV4 {
        "ks-tr-exempt-host"
    } else {
        "ks-pkt-exempt-host"
    };
    WfpFilterSpec {
        layer,
        action: WfpAction::Permit,
        remote_ip: Some(ip),
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight,
        id: filter_id_for(sid, KILLSWITCH_ROLE, "", kind, &ip.to_string()),
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

/// below-ALE proto-agnostic permit for a
/// known-primary destination host under a fail-closed block-all, at `layer`.
/// Distinct id kind from [`packet_exempt_host`] so a primary IP that happens
/// to equal a VPN-server IP does not collide filter ids. `user_sid = None`
/// (no ALE ids below the ALE layers). Layer-specific kind tag — see
/// [`packet_block`].
pub(super) fn packet_permit_primary_host(
    sid: &str,
    layer: WfpLayerKey,
    ip: Ipv4Addr,
    weight: u64,
) -> WfpFilterSpec {
    let kind = if layer == WfpLayerKey::OutboundTransportV4 {
        "ks-tr-primary-host"
    } else {
        "ks-pkt-primary-host"
    };
    packet_permit_host_with_kind(sid, layer, ip, weight, kind)
}

/// packet-layer permit for a KNOWN-DIRECT destination.
/// Same shape as [`packet_permit_primary_host`] with its own id kind so a
/// destination that is both known-primary and known-direct keeps distinct ids.
pub(super) fn packet_permit_direct_host(
    sid: &str,
    layer: WfpLayerKey,
    ip: Ipv4Addr,
    weight: u64,
) -> WfpFilterSpec {
    let kind = if layer == WfpLayerKey::OutboundTransportV4 {
        "ks-tr-direct-host"
    } else {
        "ks-pkt-direct-host"
    };
    packet_permit_host_with_kind(sid, layer, ip, weight, kind)
}

/// Packet-layer proto-agnostic permit for a liveness-probe target — the twin
/// of [`exempt_probe_target`] at the layer where the ICMP echo is actually
/// classified (the ALE block is TCP/UDP-narrowed; the named packet blocks are
/// what eat ICMP). Own id kind so overlapping IPs keep distinct ids.
pub(super) fn packet_permit_probe_target(
    sid: &str,
    layer: WfpLayerKey,
    ip: Ipv4Addr,
    weight: u64,
) -> WfpFilterSpec {
    let kind = if layer == WfpLayerKey::OutboundTransportV4 {
        "ks-tr-probe-host"
    } else {
        "ks-pkt-probe-host"
    };
    packet_permit_host_with_kind(sid, layer, ip, weight, kind)
}

fn packet_permit_host_with_kind(
    sid: &str,
    layer: WfpLayerKey,
    ip: Ipv4Addr,
    weight: u64,
    kind: &str,
) -> WfpFilterSpec {
    WfpFilterSpec {
        layer,
        action: WfpAction::Permit,
        remote_ip: Some(ip),
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight,
        id: filter_id_for(sid, KILLSWITCH_ROLE, "", kind, &ip.to_string()),
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

/// The named-protocol block set for one scope (`Some(ip)` = a /32 in mode A;
/// `None` = block-all in mode B), narrowed to `protocols`: one block per
/// selected named packet protocol (ICMP/IGMP/GRE/ESP). `idx` offsets weights
/// so per-destination sets in mode A never collide.
///
/// these blocks live at `OUTBOUND_TRANSPORT_V4`, NOT the packet
/// layer: the IPPACKET layers have no `FWPM_CONDITION_IP_PROTOCOL`, so every
/// protocol-narrowed packet-layer filter failed `FwpmFilterAdd0` with
/// `FWP_E_CONDITION_NOT_FOUND` since  (3 020 skips per HW run).
/// Known transport-layer gap (accepted): stack-originated IGMP and
/// kernel-injected GRE/ESP tunnels bypass the transport stack — user-space
/// ICMP (ping) and raw-socket sends are classified there.
///
/// the protocol-agnostic "Other"
/// block-all is GONE (see [`KillSwitchProtocols::wants_packet_layer`]): it was
/// system-wide and cut TCP/UDP above every ALE permit/exemption.
pub(super) fn packet_protocol_blocks(
    sid: &str,
    scope: DestScope<'_>,
    protocols: KillSwitchProtocols,
    idx: u64,
) -> Vec<WfpFilterSpec> {
    let mut out = Vec::new();
    for (k, p) in protocols.packet_named().into_iter().enumerate() {
        out.push(packet_block(
            sid,
            WfpLayerKey::OutboundTransportV4,
            scope,
            Some(p),
            PACKET_BLOCK_BASE + idx * 16 + k as u64,
        ));
    }
    out
}

/// Below-ALE egress-conditional Permit for the leak-proof pair at `layer`:
/// allow a flow **while it egresses `luid`** (the secondary adapter).
/// `user_sid = None` (no ALE ids below the ALE layers). Mirrors
/// [`permit_via_secondary`], optionally narrowed to one IP protocol —
/// protocol narrowing REQUIRES the transport layer (see [`packet_block`]).
/// Layer-specific kind tag.
pub(super) fn packet_egress_permit(
    sid: &str,
    layer: WfpLayerKey,
    scope: DestScope<'_>,
    proto: Option<u8>,
    luid: u64,
    weight: u64,
) -> WfpFilterSpec {
    let kind = if layer == WfpLayerKey::OutboundTransportV4 {
        "ks-tr-egress"
    } else {
        "ks-pkt-egress"
    };
    WfpFilterSpec {
        layer,
        action: WfpAction::Permit,
        remote_ip: None,
        remote_ip_set: scope.members(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight,
        id: filter_id_for(
            sid,
            KILLSWITCH_ROLE,
            &permit_luid_seg(luid),
            kind,
            &proto_scope_key(scope, proto),
        ),
        user_sid: None,
        app_pattern: None,
        local_interface_luid: Some(luid),
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: proto,
    }
}

/// The below-ALE leak-proof pairs for one scope, narrowed to `protocols`:
/// an egress-conditional Permit (allow while egressing the secondary adapter)
/// over a Block (fires the instant the secondary adapter drops), per selected
/// named packet protocol (ICMP/IGMP/GRE/ESP). Empty when no packet protocol
/// is selected. The pairs live at `OUTBOUND_TRANSPORT_V4` — see
/// [`packet_protocol_blocks`] for why the packet layer cannot host them, and
/// [`KillSwitchProtocols::wants_packet_layer`] for why there is no "Other" pair.
pub(super) fn packet_egress_pairs(
    sid: &str,
    scope: DestScope<'_>,
    protocols: KillSwitchProtocols,
    luid: u64,
    idx: u64,
) -> Vec<WfpFilterSpec> {
    let mut out = Vec::new();
    for (k, p) in protocols.packet_named().into_iter().enumerate() {
        out.push(packet_egress_permit(
            sid,
            WfpLayerKey::OutboundTransportV4,
            scope,
            Some(p),
            luid,
            PACKET_EXEMPT_BASE + idx * 16 + k as u64,
        ));
        out.push(packet_block(
            sid,
            WfpLayerKey::OutboundTransportV4,
            scope,
            Some(p),
            PACKET_BLOCK_BASE + idx * 16 + k as u64,
        ));
    }
    out
}
