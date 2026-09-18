// The catch-all kill-switch: layers, weights and destination fields.

use super::*;

/// Lower the **catch-all (Mode-B) kill-switch** of `plan` —
/// `killswitch_codegen::catch_all_kill_switch_filters`: the blanket
/// "block everything not exempted" for everything-via-secondary.
///
/// Handles [`PrecedenceClass::CatchAllExempt`] permits and
/// [`PrecedenceClass::CatchAllBlock`] blocks. The exact WFP layer, weight band and
/// conditions are reconstructed from the neutral flow:
///
/// - **layer** — IP family from the [`DstMatch`] variant (`SubnetV6`/`HostV6` →
///   IPv6, else IPv4); ALE-connect vs packet from [`Coverage`]
///   (`ConnectOnly` → ALE, `AllPackets` → packet, consistent with 4b). Packet-layer
///   filters carry `user_sid = None` (the layer exposes no ALE user id).
/// - **conditions** — [`EgressConstraint::OnlyVia`]`(Secondary)` → the secondary
///   `local_interface_luid`; a host/subnet [`DstMatch`] → `remote_ip` /
///   `remote_subnet` / `remote_subnet_v6`; a `/0` subnet is the family catch-all
///   and lowers to NO subnet condition (unconditional at that layer).
/// - **weight band** — `CatchAllExempt` → `CATCHALL_EXEMPT_BASE + ordinal` (ALE)
///   or `PACKET_EXEMPT_BASE + ordinal` (a concrete/egress packet exemption) or
///   `PACKET_PERMIT_BASE + ordinal` (a lone `dst = Any` permit letting an
///   UN-selected protocol escape the block-all); `CatchAllBlock` →
///   `CATCHALL_BLOCK_WEIGHT + ordinal` (ALE) or `PACKET_BLOCK_BASE + ordinal`
///   (packet). Exact weights are reproduced, so arbitration is identical.
///
/// Without a tunnel LUID only the egress-CONDITIONAL flows are dropped: their
/// condition could never match, and a blanket permit that never matches
/// black-holes everything. Address-scoped exemptions (loopback, link-local,
/// DHCP, the local control block, the tunnel's own servers, LAN subnets) need
/// no LUID at all — and they are exactly the floor the strict default block
/// depends on, which exists whether or not a tunnel is up.
/// The `no server exemptions` / `no protocol selected` safety valves are the
/// planner's concern (it emits no flows), so they need no handling here.
pub fn lower_catch_all_kill_switch(
    plan: &EnforcementPlan,
    secondary_luid: u64,
) -> Vec<WfpFilterSpec> {
    let mut out = Vec::new();
    for flow in &plan.flows {
        if !matches!(
            flow.precedence.class,
            PrecedenceClass::CatchAllExempt | PrecedenceClass::CatchAllBlock
        ) {
            continue;
        }
        // Without a tunnel LUID the whole blanket posture is off: its block
        // would stand while the egress permit that lets the tunnel through
        // could never match. Only the address-scoped permits survive — they are
        // the floor, and a floor without its block harms nothing.
        if secondary_luid == 0
            && (flow.precedence.class == PrecedenceClass::CatchAllBlock
                || matches!(flow.egress, EgressConstraint::OnlyVia(EgressRef::Secondary)))
        {
            continue;
        }
        let ord = u64::from(flow.precedence.ordinal);
        let df = DstFields::from(flow.flow.dst);
        let is_packet = flow.coverage == Coverage::AllPackets;
        // The packet layer carries no ALE user id: `user_sid = None` there.
        let user_sid = if is_packet {
            None
        } else {
            flow.principal.0.as_ref().map(|p| p.as_stored().to_string())
        };
        let local_interface_luid =
            matches!(flow.egress, EgressConstraint::OnlyVia(EgressRef::Secondary))
                .then_some(secondary_luid);
        let ip_protocol = flow.flow.protocol.map(l4proto_to_ip_number);
        // 4d — a `Program` scope is the primary-app exemption (`ALE_APP_ID`, ALE
        // only, top exempt band). It carries no remote/subnet condition.
        let app_pattern = app_pattern_of(&flow.app);
        let layer = catch_all_layer(df.is_v6, is_packet);
        let action = match flow.verdict {
            Verdict::Permit => WfpAction::Permit,
            Verdict::Block => WfpAction::Block,
        };
        let weight = catch_all_weight(
            flow.precedence.class,
            is_packet,
            &df,
            &flow.egress,
            app_pattern.is_some(),
            ord,
        );
        out.push(WfpFilterSpec {
            layer,
            action,
            remote_ip: df.remote_ip,
            remote_ip_set: Vec::new(),
            remote_ip_set_v6: Vec::new(),
            // 4d — DNS-over-primary exemptions are port-scoped (remote 53).
            remote_port: flow.flow.dst_port,
            weight,
            id: derive_catch_all_id(
                user_sid.as_deref(),
                layer,
                action,
                weight,
                // Every condition that distinguishes one exemption from
                // another. Two of these sharing an id is a phantom filter.
                &format!(
                    "{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
                    df.remote_ip,
                    flow.flow.dst_port,
                    df.remote_subnet,
                    df.remote_subnet_v6,
                    ip_protocol,
                    app_pattern,
                ),
            ),
            user_sid,
            app_pattern,
            local_interface_luid,
            remote_subnet: df.remote_subnet,
            remote_subnet_v6: df.remote_subnet_v6,
            ip_protocol,
        });
    }
    out
}

// Route lowering moved to `nrr_platform_api::route_lowering` when Linux became
// its second consumer: a route entry names an interface and a gateway on every
// OS, so there was nothing Windows-specific left in it.
pub use nrr_platform_api::route_lowering::{lower_routes, RouteTarget};

/// The WFP condition fields (and IP family) a neutral [`DstMatch`] lowers to. A
/// `/0` subnet is the whole-family catch-all → NO subnet condition (unconditional
/// at that layer), the `SubnetV*{ .., 0 }` convention from the enforcement model.
pub(super) struct DstFields {
    is_v6: bool,
    remote_ip: Option<Ipv4Addr>,
    remote_subnet: Option<(Ipv4Addr, u8)>,
    remote_subnet_v6: Option<(Ipv6Addr, u8)>,
}

impl From<DstMatch> for DstFields {
    fn from(dst: DstMatch) -> Self {
        match dst {
            DstMatch::Any => DstFields {
                is_v6: false,
                remote_ip: None,
                remote_subnet: None,
                remote_subnet_v6: None,
            },
            DstMatch::HostV4(ip) => DstFields {
                is_v6: false,
                remote_ip: Some(ip),
                remote_subnet: None,
                remote_subnet_v6: None,
            },
            DstMatch::SubnetV4 { net, prefix } => DstFields {
                is_v6: false,
                remote_ip: None,
                remote_subnet: (prefix != 0).then_some((net, prefix)),
                remote_subnet_v6: None,
            },
            DstMatch::HostV6(ip) => DstFields {
                is_v6: true,
                remote_ip: None,
                remote_subnet: None,
                remote_subnet_v6: Some((ip, 128)),
            },
            DstMatch::SubnetV6 { net, prefix } => DstFields {
                is_v6: true,
                remote_ip: None,
                remote_subnet: None,
                remote_subnet_v6: (prefix != 0).then_some((net, prefix)),
            },
        }
    }
}

/// Pick the WFP layer for a catch-all filter from its IP family + connect/packet
/// split.
pub(super) fn catch_all_layer(is_v6: bool, is_packet: bool) -> WfpLayerKey {
    match (is_v6, is_packet) {
        (false, false) => WfpLayerKey::AleAuthConnectV4,
        // The V4 below-ALE catch-all set (named-protocol blocks +
        // the exemptions shielding them) lives at OUTBOUND_TRANSPORT_V4: the
        // packet layer has no FWPM_CONDITION_IP_PROTOCOL, so the narrowed
        // blocks could never install there. Mirrors
        // `killswitch_codegen::catch_all_kill_switch_filters`.
        (false, true) => WfpLayerKey::OutboundTransportV4,
        (true, false) => WfpLayerKey::AleAuthConnectV6,
        // The V6 catch-all block is proto-agnostic, so it stays at the packet
        // layer (which also sees kernel-injected traffic).
        (true, true) => WfpLayerKey::OutboundIpPacketV6,
    }
}

/// The catch-all weight band for a `(class, layer, match)` combination. An ALE
/// `CatchAllExempt` with an app scope is the primary-app exemption (top band); a
/// packet `CatchAllExempt` splits into the EXEMPT band (a concrete/egress
/// exemption) vs the PERMIT band (a lone `dst = Any` permit for an UN-selected
/// protocol above the block-all).
pub(super) fn catch_all_weight(
    class: PrecedenceClass,
    is_packet: bool,
    df: &DstFields,
    egress: &EgressConstraint,
    has_app: bool,
    ord: u64,
) -> u64 {
    match class {
        // 4d — the primary-app exemption sits in the top exempt band (ALE only).
        PrecedenceClass::CatchAllExempt if !is_packet && has_app => APP_EXEMPT_BASE + ord,
        PrecedenceClass::CatchAllExempt if !is_packet => CATCHALL_EXEMPT_BASE + ord,
        PrecedenceClass::CatchAllExempt => {
            let is_exemption = matches!(egress, EgressConstraint::OnlyVia(_))
                || df.remote_ip.is_some()
                || df.remote_subnet.is_some()
                || df.remote_subnet_v6.is_some();
            if is_exemption {
                PACKET_EXEMPT_BASE + ord
            } else {
                PACKET_PERMIT_BASE + ord
            }
        }
        PrecedenceClass::CatchAllBlock if !is_packet => CATCHALL_BLOCK_WEIGHT + ord,
        PrecedenceClass::CatchAllBlock => PACKET_BLOCK_BASE + ord,
        // Not reachable — `lower_catch_all_kill_switch` filters to the two
        // catch-all classes before calling this.
        _ => CATCHALL_EXEMPT_BASE + ord,
    }
}

/// Deterministic id for a catch-all filter.
///
/// `discriminator` must carry everything else that makes two filters in this
/// band different from each other. For the true catch-all it is empty —
/// `(sid, layer, action, weight)` really is the whole identity there, since each
/// band uses each weight once. The exemption band is NOT like that: those
/// filters differ by remote address, port, subnet and app, and seeding without
/// them made two of them share an id. A colliding add returns
/// `FWP_E_ALREADY_EXISTS`, which `execute_batch` counts as success — a phantom
/// filter: recorded as installed, absent from WFP, enforcing nothing.
///
/// The behavioural oracle cannot catch this: it compares behaviour and ignores
/// ids and weights by construction.
pub(super) fn derive_catch_all_id(
    sid: Option<&str>,
    layer: WfpLayerKey,
    action: WfpAction,
    weight: u64,
    discriminator: &str,
) -> WfpFilterId {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let seed = format!(
        "catchall|{}|{}|{}|{weight}|{discriminator}",
        sid.unwrap_or(""),
        nrr_platform_api::wfp_behavioral::layer_ord(layer),
        nrr_platform_api::wfp_behavioral::action_ord(action),
    );
    let mut h = FNV_OFFSET;
    for b in seed.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    WfpFilterId::from_raw(h)
}
