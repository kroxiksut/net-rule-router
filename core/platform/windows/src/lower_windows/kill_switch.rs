// Per-destination and per-app kill-switch filters, and the set helpers
// they share.

use super::*;

/// Lower the **per-destination / per-app kill-switch**
/// of `plan` — the [`PrecedenceClass::KillSwitchPermit`] pins and the
/// [`PrecedenceClass::KillSwitchBlock`] fail-closed blocks. Each flow lowers by
/// its `(class, egress, coverage, dst/app)` shape, reconstructing
/// `killswitch_codegen`'s `kill_switch_filters` / `app_kill_switch_filters` /
/// `fail_closed_block_destinations` / `fail_closed_block_apps`:
///
/// | class | `egress` | `coverage` | scope | Lowers to |
/// |---|---|---|---|---|
/// | `KillSwitchPermit` | `OnlyVia(Secondary)` | `ConnectOnly` | `HostV4` | **ALE chunk pair** — the destinations are packed ([`nrr_platform_api::wfp_slotting`]) and each chunk gets a permit carrying the secondary `local_interface_luid` (`KILLSWITCH_PERMIT_BASE + chunk`) over a `Block` (`KILLSWITCH_BLOCK_BASE + chunk`) at `AleAuthConnectV4` (4a). |
/// | `KillSwitchPermit` | `OnlyVia(Secondary)` | `ConnectOnly` | `Program` | **ALE app pair** — keyed on `ALE_APP_ID` instead of a remote IP (4d). |
/// | `KillSwitchPermit` | `OnlyVia(Secondary)` | `AllPackets` | `HostV4` | **packed packet pair** — the egress-conditional permit-over-block per chunk per `flow.protocol`, `user_sid = None` (4b). |
/// | `KillSwitchPermit` | `Any` | `AllPackets` | `HostV4` | **packet permit** — a lone `Permit` (`PACKET_PERMIT_BASE + ordinal`) letting an UN-selected protocol escape the block-all (4b). |
/// | `KillSwitchBlock` | — | `ConnectOnly` | `HostV4` | **packed ALE block** (`KILLSWITCH_BLOCK_BASE` band), narrowed to `flow.protocol` (4d fail-closed). |
/// | `KillSwitchBlock` | — | `ConnectOnly` | `Program` | **ALE app block** (proto-agnostic) (4d fail-closed). |
/// | `KillSwitchBlock` | — | `AllPackets` | `HostV4` | **packed packet block** (`PACKET_BLOCK_BASE` band) (4d fail-closed). |
///
/// The neutral plan stays PER-DESTINATION — which addresses are pinned is
/// policy. Packing them into few filters is Windows mechanism (WFP ORs
/// same-field conditions), shared with `killswitch_codegen` through
/// `wfp_slotting` so the behavioral oracle sees identical chunk keys from both
/// pipelines. Weights are band + chunk index — the oracle ignores the literal
/// values, and only band membership arbitrates.
///
/// Fails OPEN on `secondary_luid == 0` (an unresolvable LUID would black-hole
/// the protected set) — exactly like the current codegen. `secondary_luid` is
/// resolved by the caller (the [`EgressRef`] → LUID mapping is a lowering-time,
/// per-OS concern, absent from the neutral plan).
pub fn lower_kill_switch(plan: &EnforcementPlan, secondary_luid: u64) -> Vec<WfpFilterSpec> {
    if secondary_luid == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    // Per-destination flows are COLLECTED, then packed into chunks below —
    // the standing-filter-count fix. App pairs and lone permits stay per-flow.
    let mut ale_pins = SetCollect::default();
    let mut packet_pins = ProtoSetCollect::default();
    let mut fc_ale = ProtoSetCollect::default();
    let mut fc_packet = ProtoSetCollect::default();
    for flow in &plan.flows {
        let ord = u64::from(flow.precedence.ordinal);
        let user_sid = flow.principal.0.as_ref().map(|p| p.as_stored().to_string());
        let proto = flow.flow.protocol.map(l4proto_to_ip_number);
        let app = app_pattern_of(&flow.app);
        match flow.precedence.class {
            // 4a/4b/4d(app) — the leak-proof `OnlyVia` pins + packet flows.
            PrecedenceClass::KillSwitchPermit if flow.verdict == Verdict::Permit => {
                match (&flow.egress, flow.coverage, flow.flow.dst, app.as_deref()) {
                    // 4d — ALE per-APP egress-conditional pair (the 4a pair keyed on
                    // `ALE_APP_ID` instead of a remote IP).
                    (
                        EgressConstraint::OnlyVia(EgressRef::Secondary),
                        Coverage::ConnectOnly,
                        DstMatch::Any,
                        Some(pat),
                    ) => {
                        out.push(ale_app_egress_permit(
                            pat,
                            secondary_luid,
                            KILLSWITCH_PERMIT_BASE + ord,
                            user_sid.clone(),
                        ));
                        out.push(ale_app_block(
                            pat,
                            APP_KILLSWITCH_BLOCK_BASE + ord,
                            user_sid,
                        ));
                    }
                    // 4a — ALE egress-conditional pin (proto-agnostic): collect.
                    // Either family: the chunk's own family picks the layer,
                    // and a v6 pin over a tunnel that carries no v6 is a
                    // permit that cannot match — which is the block the rule
                    // asked for, stated once.
                    (
                        EgressConstraint::OnlyVia(EgressRef::Secondary),
                        Coverage::ConnectOnly,
                        DstMatch::HostV4(ip),
                        None,
                    ) => ale_pins.push(IpAddr::V4(ip), user_sid),
                    (
                        EgressConstraint::OnlyVia(EgressRef::Secondary),
                        Coverage::ConnectOnly,
                        DstMatch::HostV6(ip),
                        None,
                    ) => ale_pins.push(IpAddr::V6(ip), user_sid),
                    // 4b — packet-layer egress-conditional pin: collect per proto.
                    (
                        EgressConstraint::OnlyVia(EgressRef::Secondary),
                        Coverage::AllPackets,
                        DstMatch::HostV4(ip),
                        None,
                    ) => packet_pins.push(proto, IpAddr::V4(ip), None),
                    // 4b — a lone packet permit so an UN-selected protocol keeps flowing
                    // above the "Other" block-all (no egress condition, no block twin).
                    (EgressConstraint::Any, Coverage::AllPackets, DstMatch::HostV4(ip), None) => {
                        out.push(packet_permit(ip, PACKET_PERMIT_BASE + ord, proto));
                    }
                    _ => {}
                }
            }
            // 4d — fail-closed blocks: the secondary is gone, so these are
            // UNCONDITIONAL blocks (no egress permit twin) at the block band.
            PrecedenceClass::KillSwitchBlock if flow.verdict == Verdict::Block => {
                match (flow.coverage, flow.flow.dst, app.as_deref()) {
                    // per-app ALE block (proto-agnostic).
                    (Coverage::ConnectOnly, DstMatch::Any, Some(pat)) => {
                        out.push(ale_app_block(
                            pat,
                            APP_KILLSWITCH_BLOCK_BASE + ord,
                            user_sid,
                        ));
                    }
                    // ALE destination block (narrowed to the ALE protocol): collect.
                    (Coverage::ConnectOnly, DstMatch::HostV4(ip), None) => {
                        fc_ale.push(proto, IpAddr::V4(ip), user_sid);
                    }
                    // Same group as its v4 twin: the codegen packs one address
                    // set across both families, and a separate group here would
                    // restart the chunk index and shift every v6 weight.
                    (Coverage::ConnectOnly, DstMatch::HostV6(ip), None) => {
                        fc_ale.push(proto, IpAddr::V6(ip), user_sid);
                    }
                    // packet destination block: collect per proto.
                    (Coverage::AllPackets, DstMatch::HostV4(ip), None) => {
                        fc_packet.push(proto, IpAddr::V4(ip), None);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    // Packed emission. Chunk index plays the destination index's old role in
    // the weight formulas; the packet window stays 16 wide per chunk.
    for (idx, chunk) in pack_both(ale_pins.ips.iter().copied()).iter().enumerate() {
        let idx = idx as u64;
        out.push(ale_set_filter(
            WfpAction::Permit,
            chunk,
            None,
            KILLSWITCH_PERMIT_BASE + idx,
            ale_pins.user_sid.clone(),
            Some(secondary_luid),
        ));
        out.push(ale_set_filter(
            WfpAction::Block,
            chunk,
            None,
            KILLSWITCH_BLOCK_BASE + idx,
            ale_pins.user_sid.clone(),
            None,
        ));
    }
    for (k, (proto, ips)) in packet_pins.groups.iter().enumerate() {
        for (idx, chunk) in pack_v4(only_v4(ips)).iter().enumerate() {
            let w = (idx as u64) * 16 + k as u64;
            out.push(packet_set_filter(
                WfpAction::Permit,
                chunk,
                *proto,
                PACKET_EXEMPT_BASE + w,
                Some(secondary_luid),
            ));
            out.push(packet_set_filter(
                WfpAction::Block,
                chunk,
                *proto,
                PACKET_BLOCK_BASE + w,
                None,
            ));
        }
    }
    // The ALE fail-closed set carries at most one protocol narrow (the codegen
    // collapses TCP/UDP into a single `ale_protocol`), so the plain `+ idx`
    // weight — the codegen's exact formula — cannot collide across groups.
    for (proto, ips) in &fc_ale.groups {
        for (idx, chunk) in pack_both(ips.iter().copied()).iter().enumerate() {
            out.push(ale_set_filter(
                WfpAction::Block,
                chunk,
                *proto,
                KILLSWITCH_BLOCK_BASE + idx as u64,
                fc_ale.user_sid.clone(),
                None,
            ));
        }
    }
    for (k, (proto, ips)) in fc_packet.groups.iter().enumerate() {
        for (idx, chunk) in pack_v4(only_v4(ips)).iter().enumerate() {
            out.push(packet_set_filter(
                WfpAction::Block,
                chunk,
                *proto,
                PACKET_BLOCK_BASE + (idx as u64) * 16 + k as u64,
                None,
            ));
        }
    }
    out
}

/// The IPv4 half of a mixed collection. The below-ALE layers this build models
/// are IPv4 only, so their collectors narrow here rather than pretending the
/// other family never arrived.
pub(super) fn only_v4(ips: &[IpAddr]) -> Vec<Ipv4Addr> {
    ips.iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            IpAddr::V6(_) => None,
        })
        .collect()
}

/// Destination collector for the packed ALE pin pair. The principal is
/// identical across a per-SID plan's flows; the first one seen is kept.
#[derive(Default)]
struct SetCollect {
    user_sid: Option<String>,
    ips: Vec<IpAddr>,
}

impl SetCollect {
    fn push(&mut self, ip: IpAddr, user_sid: Option<String>) {
        if self.user_sid.is_none() {
            self.user_sid = user_sid;
        }
        self.ips.push(ip);
    }
}

/// Destination collector grouped by protocol, in first-seen protocol order —
/// the packed twin of the per-proto filter fan-out.
#[derive(Default)]
struct ProtoSetCollect {
    user_sid: Option<String>,
    groups: Vec<(Option<u8>, Vec<IpAddr>)>,
}

impl ProtoSetCollect {
    fn push(&mut self, proto: Option<u8>, ip: IpAddr, user_sid: Option<String>) {
        if self.user_sid.is_none() {
            self.user_sid = user_sid;
        }
        match self.groups.iter_mut().find(|(p, _)| *p == proto) {
            Some((_, ips)) => ips.push(ip),
            None => self.groups.push((proto, vec![ip])),
        }
    }
}

/// ALE-connect filter over a packed chunk (permit carries the egress LUID —
/// the pin's conditional half; block carries none). Mirrors
/// `killswitch_codegen::permit_via_secondary` / `block_off_secondary` /
/// `ale_block` in their packed form.
pub(super) fn ale_set_filter(
    action: WfpAction,
    chunk: &FamilyChunk,
    proto: Option<u8>,
    weight: u64,
    user_sid: Option<String>,
    egress_luid: Option<u64>,
) -> WfpFilterSpec {
    let layer = match chunk {
        FamilyChunk::V4(_) => WfpLayerKey::AleAuthConnectV4,
        FamilyChunk::V6(_) => WfpLayerKey::AleAuthConnectV6,
    };
    let (members_v4, members_v6) = match chunk {
        FamilyChunk::V4(c) => (c.members.clone(), Vec::new()),
        FamilyChunk::V6(c) => (Vec::new(), c.members.clone()),
    };
    WfpFilterSpec {
        layer,
        action,
        remote_ip: None,
        remote_ip_set: members_v4,
        remote_ip_set_v6: members_v6,
        remote_port: None,
        weight,
        id: derive_set_id(user_sid.as_deref(), layer, action, &chunk.id_seg(), weight),
        user_sid,
        app_pattern: None,
        local_interface_luid: egress_luid,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: proto,
    }
}

/// Below-ALE filter over a packed chunk (`user_sid = None` — no ALE ids below
/// the ALE layers). Layer picked by [`below_ale_layer_for`]. Mirrors
/// `killswitch_codegen::packet_egress_permit` / `packet_block` packed.
pub(super) fn packet_set_filter(
    action: WfpAction,
    chunk: &V4SlotChunk,
    proto: Option<u8>,
    weight: u64,
    egress_luid: Option<u64>,
) -> WfpFilterSpec {
    let layer = below_ale_layer_for(proto);
    WfpFilterSpec {
        layer,
        action,
        remote_ip: None,
        remote_ip_set: chunk.members.clone(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight,
        id: derive_set_id(None, layer, action, &chunk.id_seg(), weight),
        user_sid: None,
        app_pattern: None,
        local_interface_luid: egress_luid,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: proto,
    }
}
