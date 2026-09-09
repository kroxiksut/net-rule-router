//! Windows LOWERING of the neutral [`EnforcementPlan`] into WFP filters.
//!
//! This is the Windows half of the C-hybrid seam: it takes the OS-neutral plan
//! built by `nrr_service_runtime::enforcement_planner` and produces
//! [`WfpFilterSpec`]s, reconstructing the Windows-specific weight bands and
//! deterministic ids that used to live inside `wfp_codegen` /
//! `killswitch_codegen`. The Windows id/weight *vocabulary* is allowed to live
//! here (it is not a cross-OS leak); the neutral plan carries none of it.
//! Each lowering function is proven behaviourally equivalent to the legacy
//! codegen path it replaces via the `nrr_platform_api::wfp_behavioral` oracle.
//!
//! ## Function responsibilities
//!
//! - [`lower_route_rules`] covers the full rule-driven surface of
//!   `wfp_codegen::generate_filters` — `RouteRule`/`HardBlock` host filters
//!   (`DstMatch::HostV4`, weight `base + ordinal`, Block adds the packet-layer
//!   mirror) and `AppScope::Program` app-id filters (`DstMatch::Any`, one per
//!   exe path; non-handled flows are skipped) — plus the
//!   [`PrecedenceClass::DefaultCatchAll`] `StrictSecondaryFailClosed` default
//!   block (`wfp_codegen::default_block_spec`).
//! - [`lower_kill_switch`] covers the per-destination kill-switch of
//!   `killswitch_codegen::kill_switch_filters` — the ALE `OnlyVia(Secondary)`
//!   permit-over-block pair plus the packet-layer (`OutboundIpPacketV4`)
//!   multi-protocol egress pairs and "Other" block-all with per-protocol
//!   permit exceptions, keyed on `(egress, coverage)` — plus the ALE per-app
//!   egress pairs (`app_kill_switch_filters`) and the
//!   [`PrecedenceClass::KillSwitchBlock`] fail-closed IP/app/packet blocks
//!   (`fail_closed_block_destinations` / `fail_closed_block_apps`).
//! - [`lower_catch_all_kill_switch`] covers the catch-all (Mode-B) kill-switch
//!   of `killswitch_codegen::catch_all_kill_switch_filters` — the blanket
//!   egress permit + loopback/link-local/broadcast/server/LAN subnet
//!   exemptions, the ALE + packet catch-all blocks, and the IPv6 cut (all
//!   four WFP layers), keyed on `(class, coverage, dst-family, egress)` —
//!   plus the primary-app exemption (`APP_EXEMPT_BASE`, from
//!   `primary_app_exempt_filters`), the DNS-over-primary port-53 permits, and
//!   the Mode-B block-all (`fail_closed_block_all_filters`).
//! - [`lower_routes`] turns the neutral
//!   [`RouteIntent`](nrr_platform_api::enforcement::RouteIntent)s into
//!   route-table entries (`route_codegen::generate_routes`).

use std::net::{Ipv4Addr, Ipv6Addr};

use nrr_platform_api::enforcement::{
    AppScope, Coverage, DstMatch, EgressConstraint, EgressRef, EnforcementPlan, FlowRule, L4Proto,
    PrecedenceClass, Verdict,
};
use nrr_platform_api::types::{WfpAction, WfpFilterId, WfpFilterSpec, WfpLayerKey};
use nrr_platform_api::wfp_slotting::{pack_v4, V4SlotChunk};
use nrr_shared::RouteRole;

// Weight base bands, mirrored from the current `wfp_codegen` so the RELATIVE
// arbitration order is identical (the absolute values need not be — the
// behavioral oracle ignores literal weights, but preserves their order):
// primary route rules outrank secondary; the role-independent Block band sits
// above both.
const BASE_PRIMARY: u64 = 0x0020_0000;
const BASE_SECONDARY: u64 = 0x0010_0000;
// A band of its own, ABOVE the app exemptions: both used to sit on
// `0x0060_0000`, and all of these filters live on one ALE layer in one
// sub-layer, where the highest weight wins. A user's explicit Block and the
// kill-switch's primary-app exemption arbitrating by accident is not a trade-off
// anyone chose — and `CLEAR_ACTION_RIGHT` does not settle it, since it defends a
// Block against OTHER sub-layers, not against our own higher-weighted permit.
const BASE_BLOCK: u64 = 0x0070_0000;
// Kill-switch bands, mirrored from `killswitch_codegen`: the egress-conditional
// permit sits above its unconditional block (both above the route-rule bands),
// so "permit only while egressing the secondary adapter, else block" arbitrates
// correctly.
const KILLSWITCH_PERMIT_BASE: u64 = 0x0040_0000;
const KILLSWITCH_BLOCK_BASE: u64 = 0x0030_0000;
// The fake-IP pool, mirrored from `killswitch_codegen::FAKEIP_POOL_PERMIT_BASE`:
// the top of the kill-switch permit band, so an application always reaches the
// relay's virtual addresses — a pool cut is every fake-routed host dead.
const FAKEIP_POOL_PERMIT_BASE: u64 = KILLSWITCH_PERMIT_BASE + 0x000E_0000;
// Per-APP kill-switch / fail-closed block band, mirrored from
// `killswitch_codegen::APP_KILLSWITCH_BLOCK_BASE`. Like the catch-all, it sits
// BETWEEN the secondary and primary rule bands: a primary rule's own permit
// outranks it, so every main-named address keeps working for a pinned app —
// uncapped, replacing the 64-entry per-(app, address) rescue permits.
const APP_KILLSWITCH_BLOCK_BASE: u64 = 0x001C_0000;
// DoH/DoT lockdown band, mirrored from `killswitch_codegen::DOH_BLOCK_BASE`.
// Between the primary rule band (`0x0020_0000`) and the kill-switch block
// band (`0x0030_0000`).
const DOH_BLOCK_BASE: u64 = 0x0028_0000;
// Packet-layer (`OUTBOUND_IPPACKET_V4`) kill-switch bands, mirrored
// from `killswitch_codegen`. This layer arbitrates SEPARATELY from the ALE connect
// layer, so the numeric space is reused: within the packet layer the ordering
// (high → low) is egress/exempt permits, then permit-unselected, then blocks — so
// loopback / the tunnel / any UN-selected protocol always escapes the block. The
// neutral `ordinal` already folds the per-destination `idx * 16` window (see
// `enforcement_planner::PACKET_SLOTS_PER_DEST`), so the weight is `base + ordinal`.
const PACKET_EXEMPT_BASE: u64 = 0x0250_0000;
const PACKET_PERMIT_BASE: u64 = 0x0140_0000;
const PACKET_BLOCK_BASE: u64 = 0x0030_0000;
// Catch-all (Mode-B) kill-switch bands, mirrored from
// `killswitch_codegen`. The ALE exemptions sit above every rule band and above
// the per-destination kill-switch bands; the catch-all block sits deliberately
// BETWEEN the secondary rule band (`0x0010_0000`) and the primary rule band
// (`0x0020_0000`) so primary exceptions escape it while secondary destinations
// are cut. The V6 layers arbitrate separately, so they reuse these numbers.
const CATCHALL_EXEMPT_BASE: u64 = 0x0050_0000;
const CATCHALL_BLOCK_WEIGHT: u64 = 0x0018_0000;
// Primary-app kill-switch exemption band, mirrored from
// `killswitch_codegen`. Above `CATCHALL_EXEMPT_BASE` so a user's primary-routed
// app permit outranks every kill-switch / fail-closed / block-all filter — the
// VPN-bootstrap fix (a deliberately primary-routed app is never a leak to cut).
const APP_EXEMPT_BASE: u64 = 0x0060_0000;
// Fail-closed default catch-all block weight, mirrored from
// `wfp_codegen::DEFAULT_BLOCK_WEIGHT`. Below every per-rule band so a rule-driven
// `Permit` always wins over the StrictSecondaryFailClosed default block.
const DEFAULT_BLOCK_WEIGHT: u64 = 0x0000_FFFF;

// Compile-time guard over the mirrored bands: the ordering above is the whole
// point of mirroring them, and two bands sharing a base silently lose it.
const _: () = {
    assert!(BASE_BLOCK > APP_EXEMPT_BASE);
    assert!(APP_EXEMPT_BASE > CATCHALL_EXEMPT_BASE);
    assert!(CATCHALL_EXEMPT_BASE > FAKEIP_POOL_PERMIT_BASE);
    assert!(FAKEIP_POOL_PERMIT_BASE > KILLSWITCH_PERMIT_BASE);
    assert!(KILLSWITCH_PERMIT_BASE > KILLSWITCH_BLOCK_BASE);
    assert!(KILLSWITCH_BLOCK_BASE > DOH_BLOCK_BASE);
    assert!(DOH_BLOCK_BASE > BASE_PRIMARY);
    assert!(BASE_PRIMARY > APP_KILLSWITCH_BLOCK_BASE);
    assert!(APP_KILLSWITCH_BLOCK_BASE > CATCHALL_BLOCK_WEIGHT);
    assert!(CATCHALL_BLOCK_WEIGHT > BASE_SECONDARY);
    assert!(BASE_SECONDARY > DEFAULT_BLOCK_WEIGHT);
};

/// Lower the address-match route rules of `plan` to WFP filters.
///
/// Handles [`PrecedenceClass::RouteRule`] permits and
/// [`PrecedenceClass::HardBlock`] blocks matching a
/// [`DstMatch::HostV4`]; other flows are handled by other lowering functions
/// and are skipped here.
/// The weight is `base + ordinal` (the planner folds `pos * SLOTS_PER_RULE +
/// fanout_idx` into `ordinal`), preserving the current arbitration order. A
/// `Block` with [`Coverage::AllPackets`] additionally emits the packet-layer
/// mirror (`user_sid = None`) so ICMP/etc. to that IP is dropped too — matching
/// `wfp_codegen::push_packet_block_mirror`. Ids are deterministic (re-apply = no
/// churn) but need NOT match the old FNV scheme — the oracle ignores ids.
pub fn lower_route_rules(plan: &EnforcementPlan) -> Vec<WfpFilterSpec> {
    // Host flows are COLLECTED per rule and packed; everything else (app
    // filters, the default catch-all) lowers one flow at a time.
    //
    // The neutral plan stays per-address — which addresses a rule covers is
    // policy. Folding them into chunk filters is Windows mechanism (WFP ORs
    // conditions on one field), shared with `wfp_codegen` through
    // `wfp_slotting` so both pipelines produce identical chunk keys and the
    // behavioural oracle still compares like with like.
    let mut out = Vec::new();
    let mut rules: Vec<(RuleChunkKey, Vec<Ipv4Addr>)> = Vec::new();
    for flow in &plan.flows {
        match rule_chunk_key(flow) {
            Some((key, ip)) => match rules.iter_mut().find(|(k, _)| *k == key) {
                Some((_, ips)) => ips.push(ip),
                None => rules.push((key, vec![ip])),
            },
            None => out.extend(lower_flow(flow)),
        }
    }
    for (key, ips) in rules {
        for (idx, chunk) in nrr_platform_api::wfp_slotting::pack_v4(ips)
            .into_iter()
            .enumerate()
        {
            let weight = key.base
                + key.rule_position * nrr_platform_api::enforcement::SLOTS_PER_RULE
                + key.slot_base
                + idx as u64;
            out.push(make_chunk_filter(
                WfpLayerKey::AleAuthConnectV4,
                key.action,
                &chunk,
                weight,
                key.user_sid.clone(),
            ));
            // A Block with packet coverage drops the destination at the packet
            // layer too; that layer exposes no ALE user id.
            if key.action == WfpAction::Block && key.all_packets {
                out.push(make_chunk_filter(
                    WfpLayerKey::OutboundIpPacketV4,
                    WfpAction::Block,
                    &chunk,
                    weight,
                    None,
                ));
            }
        }
    }
    out
}

/// What makes two host flows part of the SAME packed rule.
///
/// The ordinal the planner assigns is `rule_position * SLOTS_PER_RULE +
/// fanout_index`, so dividing it recovers the rule and every address of one
/// rule lands in one group. Everything else in the key is what a filter would
/// carry anyway — mixing two of them into one chunk would change what the
/// filter means.
#[derive(Clone, PartialEq, Eq)]
struct RuleChunkKey {
    base: u64,
    rule_position: u64,
    /// First slot of the range this group occupies. A rule's own addresses
    /// start at 0; the addresses its application was OBSERVED using start after
    /// the per-executable app-id filters. Packing the two together would put a
    /// filter in a slot the codegen reserved for the other kind.
    slot_base: u64,
    action: WfpAction,
    all_packets: bool,
    user_sid: Option<String>,
}

/// `Some((key, ip))` for a plain per-address rule flow; `None` for anything
/// that is not one (an app filter, the default catch-all, a non-rule class).
fn rule_chunk_key(flow: &FlowRule) -> Option<(RuleChunkKey, Ipv4Addr)> {
    let base = base_for_class(flow.precedence.class)?;
    if matches!(flow.app, AppScope::Program { .. }) {
        return None;
    }
    let DstMatch::HostV4(ip) = flow.flow.dst else {
        return None;
    };
    let action = match flow.verdict {
        Verdict::Permit => WfpAction::Permit,
        Verdict::Block => WfpAction::Block,
    };
    let ordinal = u64::from(flow.precedence.ordinal);
    let slot = ordinal % nrr_platform_api::enforcement::SLOTS_PER_RULE;
    let observed_app_range = nrr_platform_api::enforcement::APP_PATH_FANOUT_CAP + 1;
    Some((
        RuleChunkKey {
            base,
            rule_position: ordinal / nrr_platform_api::enforcement::SLOTS_PER_RULE,
            slot_base: if slot >= observed_app_range {
                observed_app_range
            } else {
                0
            },
            action,
            all_packets: flow.coverage == Coverage::AllPackets,
            user_sid: flow.principal.0.as_ref().map(|p| p.as_stored().to_string()),
        },
        ip,
    ))
}

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
                    (
                        EgressConstraint::OnlyVia(EgressRef::Secondary),
                        Coverage::ConnectOnly,
                        DstMatch::HostV4(ip),
                        None,
                    ) => ale_pins.push(ip, user_sid),
                    // 4b — packet-layer egress-conditional pin: collect per proto.
                    (
                        EgressConstraint::OnlyVia(EgressRef::Secondary),
                        Coverage::AllPackets,
                        DstMatch::HostV4(ip),
                        None,
                    ) => packet_pins.push(proto, ip, None),
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
                        fc_ale.push(proto, ip, user_sid);
                    }
                    // packet destination block: collect per proto.
                    (Coverage::AllPackets, DstMatch::HostV4(ip), None) => {
                        fc_packet.push(proto, ip, None);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    // Packed emission. Chunk index plays the destination index's old role in
    // the weight formulas; the packet window stays 16 wide per chunk.
    for (idx, chunk) in pack_v4(ale_pins.ips.iter().copied()).iter().enumerate() {
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
        for (idx, chunk) in pack_v4(ips.iter().copied()).iter().enumerate() {
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
        for (idx, chunk) in pack_v4(ips.iter().copied()).iter().enumerate() {
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
        for (idx, chunk) in pack_v4(ips.iter().copied()).iter().enumerate() {
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

/// Destination collector for the packed ALE pin pair. The principal is
/// identical across a per-SID plan's flows; the first one seen is kept.
#[derive(Default)]
struct SetCollect {
    user_sid: Option<String>,
    ips: Vec<Ipv4Addr>,
}

impl SetCollect {
    fn push(&mut self, ip: Ipv4Addr, user_sid: Option<String>) {
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
    groups: Vec<(Option<u8>, Vec<Ipv4Addr>)>,
}

impl ProtoSetCollect {
    fn push(&mut self, proto: Option<u8>, ip: Ipv4Addr, user_sid: Option<String>) {
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
fn ale_set_filter(
    action: WfpAction,
    chunk: &V4SlotChunk,
    proto: Option<u8>,
    weight: u64,
    user_sid: Option<String>,
    egress_luid: Option<u64>,
) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action,
        remote_ip: None,
        remote_ip_set: chunk.members.clone(),
        remote_port: None,
        weight,
        id: derive_set_id(
            user_sid.as_deref(),
            WfpLayerKey::AleAuthConnectV4,
            action,
            &chunk.id_seg(),
            weight,
        ),
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
fn packet_set_filter(
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

/// Lower the DoH/DoT lockdown plan
/// ([`enforcement_planner::plan_doh_dot_block`]) to WFP filters. `HostV4`
/// [`PrecedenceClass::DohBlock`] flows are grouped by `(dst_port, protocol)`
/// and packed — one ALE-connect `Block` per chunk — reproducing the packed
/// `killswitch_codegen::doh_dot_block_filters`; `Any` flows (the global DoT
/// cut) stay unconditional.
pub fn lower_doh_dot_block(plan: &EnforcementPlan) -> Vec<WfpFilterSpec> {
    // Grouped by port, protocols in first-seen order — emission then walks
    // chunk × protocol with one running weight, then the global (`Any`) cuts:
    // the codegen's exact weight order, which the arbitration oracle pins.
    type PortGroup = (Option<u16>, Vec<Option<u8>>, Vec<Ipv4Addr>);
    let mut port_groups: Vec<PortGroup> = Vec::new();
    let mut any_cuts: Vec<(Option<u16>, Option<u8>, Option<String>)> = Vec::new();
    let mut set_sid: Option<String> = None;
    for flow in &plan.flows {
        if flow.precedence.class != PrecedenceClass::DohBlock || flow.verdict != Verdict::Block {
            continue;
        }
        let user_sid = flow.principal.0.as_ref().map(|p| p.as_stored().to_string());
        let proto = flow.flow.protocol.map(l4proto_to_ip_number);
        match flow.flow.dst {
            DstMatch::HostV4(ip) => {
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
            DstMatch::Any => any_cuts.push((flow.flow.dst_port, proto, user_sid)),
            _ => {} // DoH lockdown only emits HostV4 / Any
        }
    }
    let mut out = Vec::new();
    let mut weight = DOH_BLOCK_BASE;
    for (port, protos, ips) in &port_groups {
        for chunk in pack_v4(ips.iter().copied()) {
            for proto in protos {
                out.push(doh_port_block(
                    Some(&chunk),
                    *port,
                    *proto,
                    weight,
                    set_sid.clone(),
                ));
                weight += 1;
            }
        }
    }
    for (port, proto, user_sid) in any_cuts {
        out.push(doh_port_block(None, port, proto, weight, user_sid));
        weight += 1;
    }
    out
}

/// ALE-connect `Block` narrowed to `(chunk?, port, proto)`. Mirrors the packed
/// `killswitch_codegen::doh_port_block`.
fn doh_port_block(
    scope: Option<&V4SlotChunk>,
    remote_port: Option<u16>,
    proto: Option<u8>,
    weight: u64,
    user_sid: Option<String>,
) -> WfpFilterSpec {
    let seg = scope
        .map(V4SlotChunk::id_seg)
        .unwrap_or_else(|| "any".to_string());
    let id = derive_set_id(
        user_sid.as_deref(),
        WfpLayerKey::AleAuthConnectV4,
        WfpAction::Block,
        &format!("doh|{seg}"),
        weight,
    );
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip: None,
        remote_ip_set: scope.map(|c| c.members.clone()).unwrap_or_default(),
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
fn app_pattern_of(app: &AppScope) -> Option<String> {
    match app {
        AppScope::Any => None,
        AppScope::Program { exe_paths, .. } => {
            exe_paths.first().map(|p| p.to_string_lossy().into_owned())
        }
    }
}

/// ALE-connect per-app egress-conditional `Permit` — allow `pattern`'s process
/// only while it egresses `luid`. Mirrors `killswitch_codegen::permit_app_via_secondary`.
fn ale_app_egress_permit(
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
fn ale_app_block(pattern: &str, weight: u64, user_sid: Option<String>) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip: None,
        remote_ip_set: Vec::new(),
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
fn l4proto_to_ip_number(proto: L4Proto) -> u8 {
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
fn below_ale_layer_for(proto: Option<u8>) -> WfpLayerKey {
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
fn packet_permit(ip: Ipv4Addr, weight: u64, proto: Option<u8>) -> WfpFilterSpec {
    let layer = below_ale_layer_for(proto);
    WfpFilterSpec {
        layer,
        action: WfpAction::Permit,
        remote_ip: Some(ip),
        remote_ip_set: Vec::new(),
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

fn base_for_class(class: PrecedenceClass) -> Option<u64> {
    match class {
        PrecedenceClass::RouteRule(RouteRole::Primary) => Some(BASE_PRIMARY),
        PrecedenceClass::RouteRule(RouteRole::Secondary) => Some(BASE_SECONDARY),
        PrecedenceClass::HardBlock => Some(BASE_BLOCK),
        // The StrictSecondaryFailClosed default catch-all block sits at
        // the lowest band so any rule-driven `Permit` still wins over it.
        PrecedenceClass::DefaultCatchAll => Some(DEFAULT_BLOCK_WEIGHT),
        _ => None,
    }
}

fn lower_flow(flow: &FlowRule) -> Vec<WfpFilterSpec> {
    let Some(base) = base_for_class(flow.precedence.class) else {
        return Vec::new();
    };
    let action = match flow.verdict {
        Verdict::Permit => WfpAction::Permit,
        Verdict::Block => WfpAction::Block,
    };
    let user_sid = flow.principal.0.as_ref().map(|p| p.as_stored().to_string());
    let weight = base + u64::from(flow.precedence.ordinal);

    // The fail-closed default block (`StrictSecondaryFailClosed`): a
    // user-scoped ALE `Block` with NO remote condition at the lowest band. Matches
    // `wfp_codegen::default_block_spec`.
    if flow.precedence.class == PrecedenceClass::DefaultCatchAll
        && action == WfpAction::Block
        && matches!(flow.flow.dst, DstMatch::Any)
    {
        return vec![WfpFilterSpec {
            layer: WfpLayerKey::AleAuthConnectV4,
            action: WfpAction::Block,
            remote_ip: None,
            remote_ip_set: Vec::new(),
            remote_port: None,
            weight,
            id: derive_catch_all_id(
                user_sid.as_deref(),
                WfpLayerKey::AleAuthConnectV4,
                WfpAction::Block,
                weight,
                // The real catch-all: no conditions, so nothing else to name.
                "",
            ),
            user_sid,
            app_pattern: None,
            local_interface_luid: None,
            remote_subnet: None,
            remote_subnet_v6: None,
            ip_protocol: None,
        }];
    }

    // An `Application` flow lowers to per-exe `ALE_APP_ID` filters (no remote IP,
    // no packet mirror — the packet layer has no app context). The planner puts
    // one path per flow, but iterate defensively.
    if let AppScope::Program { exe_paths, .. } = &flow.app {
        if matches!(flow.flow.dst, DstMatch::Any) {
            return exe_paths
                .iter()
                .map(|path| WfpFilterSpec {
                    layer: WfpLayerKey::AleAuthConnectV4,
                    action,
                    remote_ip: None,
                    remote_ip_set: Vec::new(),
                    remote_port: None,
                    weight,
                    id: derive_app_id(user_sid.as_deref(), action, &path.to_string_lossy(), weight),
                    user_sid: user_sid.clone(),
                    app_pattern: Some(path.to_string_lossy().into_owned()),
                    local_interface_luid: None,
                    remote_subnet: None,
                    remote_subnet_v6: None,
                    ip_protocol: None,
                })
                .collect();
        }
    }

    let DstMatch::HostV4(ip) = flow.flow.dst else {
        return Vec::new();
    };
    let mut out = vec![make_host_filter(
        WfpLayerKey::AleAuthConnectV4,
        action,
        ip,
        weight,
        user_sid.clone(),
    )];
    // A Block with packet coverage drops the destination at the packet layer
    // too (where ICMP/IGMP/GRE/ESP live). The packet layer exposes no ALE
    // user/app condition, so the mirror MUST carry `user_sid = None`.
    if action == WfpAction::Block && flow.coverage == Coverage::AllPackets {
        out.push(make_host_filter(
            WfpLayerKey::OutboundIpPacketV4,
            WfpAction::Block,
            ip,
            weight,
            None,
        ));
    }
    out
}

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
struct DstFields {
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
fn catch_all_layer(is_v6: bool, is_packet: bool) -> WfpLayerKey {
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
fn catch_all_weight(
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
fn derive_catch_all_id(
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

fn make_host_filter(
    layer: WfpLayerKey,
    action: WfpAction,
    ip: Ipv4Addr,
    weight: u64,
    user_sid: Option<String>,
) -> WfpFilterSpec {
    let id = derive_filter_id(user_sid.as_deref(), layer, action, ip, weight);
    WfpFilterSpec {
        layer,
        action,
        remote_ip: Some(ip),
        remote_ip_set: Vec::new(),
        remote_port: None,
        weight,
        id,
        user_sid,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

/// One packed chunk as a filter. The per-address twin of this is
/// [`make_host_filter`]; identity comes from the chunk digest, so the same
/// address set always yields the same id.
fn make_chunk_filter(
    layer: WfpLayerKey,
    action: WfpAction,
    chunk: &nrr_platform_api::wfp_slotting::V4SlotChunk,
    weight: u64,
    user_sid: Option<String>,
) -> WfpFilterSpec {
    let id = derive_catch_all_id(user_sid.as_deref(), layer, action, weight, &chunk.id_seg());
    WfpFilterSpec {
        layer,
        action,
        remote_ip: None,
        remote_ip_set: chunk.members.clone(),
        remote_port: None,
        weight,
        id,
        user_sid,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

/// Deterministic id for an app-id filter (keyed on user/action/exe-path/weight —
/// no remote IP). Oracle ignores ids; this only needs to be stable + unique.
fn derive_app_id(sid: Option<&str>, action: WfpAction, path: &str, weight: u64) -> WfpFilterId {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let seed = format!(
        "app|{}|{}|{path}|{weight}",
        sid.unwrap_or(""),
        nrr_platform_api::wfp_behavioral::action_ord(action),
    );
    let mut h = FNV_OFFSET;
    for b in seed.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    WfpFilterId::from_raw(h)
}

/// Deterministic id for a packed-set filter. The chunk's id segment digests
/// the membership, so a membership change mints a new id and the reconcile
/// swaps the filter make-before-break; `weight` keeps the two halves of a
/// pair (and different bands over one chunk) apart.
fn derive_set_id(
    sid: Option<&str>,
    layer: WfpLayerKey,
    action: WfpAction,
    seg: &str,
    weight: u64,
) -> WfpFilterId {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let seed = format!(
        "set|{}|{}|{}|{seg}|{weight}",
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

/// Deterministic filter id (FNV-1a of the fields that make a filter unique in a
/// plan: user, layer, action, target, weight). Same plan → same id → a WFP
/// re-apply is a no-op. Including `layer` + `weight` keeps the id distinct for
/// the ALE/packet-mirror pair and for two fan-out targets that resolve to the
/// same IP. Its literal value is NOT part of the cross-OS contract (the oracle
/// ignores ids); it only has to be stable + unique within a build.
fn derive_filter_id(
    sid: Option<&str>,
    layer: WfpLayerKey,
    action: WfpAction,
    ip: Ipv4Addr,
    weight: u64,
) -> WfpFilterId {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let seed = format!(
        "{}|{}|{}|{}|{weight}",
        sid.unwrap_or(""),
        nrr_platform_api::wfp_behavioral::layer_ord(layer),
        nrr_platform_api::wfp_behavioral::action_ord(action),
        ip,
    );
    let mut h = FNV_OFFSET;
    for b in seed.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    WfpFilterId::from_raw(h)
}

/// Everything the Windows lowering needs that a neutral plan cannot carry:
/// identities the kernel hands out at runtime, and which change when a link
/// reconnects.
///
/// Supplied per call, never cached — the same rule the Linux side follows with
/// interface names. A stale LUID does not fail loudly; it pins traffic to an
/// interface that no longer exists while the rule still reads as applied.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EgressLuids {
    /// LUID of the additional link. `0` means "not resolvable right now" and
    /// the kill-switch lowering declines rather than guessing.
    pub secondary: u64,
}

/// One plan in, the filters that express it out.
///
/// The five `lower_*` functions above each handle one precedence class; this is
/// the composition the backend applies. Order is the arbitration order — route
/// rules, then the per-destination kill-switch, then the DoH/DoT block, then
/// the catch-all — and it is the property the oracle tests pin, not the ids.
///
/// Routes are deliberately NOT here: they are a different mechanism (the route
/// table, not the filter engine) with a different failure mode, and folding
/// them in would hide a partial apply behind one number.
pub fn lower_plan(plan: &EnforcementPlan, egress: EgressLuids) -> Vec<WfpFilterSpec> {
    let mut out = lower_route_rules(plan);
    out.extend(lower_kill_switch(plan, egress.secondary));
    out.extend(lower_doh_dot_block(plan));
    out.extend(lower_catch_all_kill_switch(plan, egress.secondary));
    out.extend(lower_fake_ip_pool(plan));
    out
}

/// The fake-IP pool band: a subnet permit per family, plus the UDP veto that
/// rides above it while the relay's UDP path is off. Ordinal IS the offset
/// inside the band — the planner emits them in the order the arbitration needs
/// (permit, then the veto that qualifies it).
pub fn lower_fake_ip_pool(plan: &EnforcementPlan) -> Vec<WfpFilterSpec> {
    let mut flows: Vec<&FlowRule> = plan
        .flows
        .iter()
        .filter(|f| f.precedence.class == PrecedenceClass::FakeIpPool)
        .collect();
    flows.sort_by_key(|f| f.precedence.ordinal);

    let mut out = Vec::new();
    for flow in flows {
        let user_sid = flow.principal.0.as_ref().map(|p| p.as_stored().to_string());
        let action = match flow.verdict {
            Verdict::Permit => WfpAction::Permit,
            Verdict::Block => WfpAction::Block,
        };
        let weight = FAKEIP_POOL_PERMIT_BASE + u64::from(flow.precedence.ordinal);
        let proto = flow.flow.protocol.map(l4proto_to_ip_number);
        let (layer, subnet_v4, subnet_v6) = match flow.flow.dst {
            DstMatch::SubnetV4 { net, prefix } => {
                (WfpLayerKey::AleAuthConnectV4, Some((net, prefix)), None)
            }
            DstMatch::SubnetV6 { net, prefix } => {
                (WfpLayerKey::AleAuthConnectV6, None, Some((net, prefix)))
            }
            // The pool is a subnet by construction; anything else in this band
            // is a planner bug, and silently lowering it would hide that.
            _ => continue,
        };
        out.push(WfpFilterSpec {
            layer,
            action,
            remote_ip: None,
            remote_ip_set: Vec::new(),
            remote_port: None,
            weight,
            id: derive_subnet_filter_id(user_sid.as_deref(), layer, action, weight),
            user_sid,
            app_pattern: None,
            local_interface_luid: None,
            remote_subnet: subnet_v4,
            remote_subnet_v6: subnet_v6,
            ip_protocol: proto,
        });
    }
    out
}

/// Identity for a subnet-scoped filter. The address itself is not part of the
/// seed because a band's subnet is fixed by configuration, while the weight
/// already separates the members of the band.
fn derive_subnet_filter_id(
    sid: Option<&str>,
    layer: WfpLayerKey,
    action: WfpAction,
    weight: u64,
) -> WfpFilterId {
    derive_filter_id(sid, layer, action, Ipv4Addr::UNSPECIFIED, weight)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::enforcement::{
        AppScope, Coverage, EgressConstraint, FlowMatch, Precedence, PrincipalScope, UserPrincipal,
    };
    use nrr_platform_api::wfp_behavioral::behaviorally_equivalent;
    use std::net::Ipv4Addr;

    fn route_flow(role: RouteRole, ordinal: u32, ip: Ipv4Addr) -> FlowRule {
        FlowRule {
            verdict: Verdict::Permit,
            precedence: Precedence {
                class: PrecedenceClass::RouteRule(role),
                ordinal,
            },
            flow: FlowMatch {
                dst: DstMatch::HostV4(ip),
                dst_port: None,
                protocol: None,
            },
            principal: PrincipalScope(UserPrincipal::from_windows_sid("S-1-5-21-A").ok()),
            app: AppScope::Any,
            egress: EgressConstraint::Any,
            coverage: Coverage::ConnectOnly,
        }
    }

    fn plan(flows: Vec<FlowRule>) -> EnforcementPlan {
        EnforcementPlan {
            principal: UserPrincipal::from_windows_sid("S-1-5-21-A")
                .unwrap_or(UserPrincipal::Baseline),
            flows,
            routes: Vec::new(),
            policy_rules: Vec::new(),
        }
    }

    fn block_flow(ordinal: u32, ip: Ipv4Addr) -> FlowRule {
        FlowRule {
            verdict: Verdict::Block,
            precedence: Precedence {
                class: PrecedenceClass::HardBlock,
                ordinal,
            },
            flow: FlowMatch {
                dst: DstMatch::HostV4(ip),
                dst_port: None,
                protocol: None,
            },
            principal: PrincipalScope(UserPrincipal::from_windows_sid("S-1-5-21-A").ok()),
            app: AppScope::Any,
            egress: EgressConstraint::Any,
            coverage: Coverage::AllPackets,
        }
    }

    #[test]
    fn lowers_exact_ip_permit_with_expected_fields() {
        let p = plan(vec![route_flow(
            RouteRole::Primary,
            0,
            Ipv4Addr::new(203, 0, 113, 5),
        )]);
        let out = lower_route_rules(&p);
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.layer, WfpLayerKey::AleAuthConnectV4);
        assert_eq!(f.action, WfpAction::Permit);
        // Packed: the address rides in the set, and `covers_v4` is the
        // question every consumer actually asks.
        assert!(f.covers_v4(Ipv4Addr::new(203, 0, 113, 5)));
        assert_eq!(f.user_sid.as_deref(), Some("S-1-5-21-A"));
        assert_eq!(f.weight, BASE_PRIMARY);
        assert!(f.app_pattern.is_none() && f.local_interface_luid.is_none());
    }

    #[test]
    fn primary_outranks_secondary_and_ids_are_deterministic() {
        let p = plan(vec![
            route_flow(RouteRole::Primary, 0, Ipv4Addr::new(1, 1, 1, 1)),
            route_flow(RouteRole::Secondary, 0, Ipv4Addr::new(2, 2, 2, 2)),
        ]);
        let a = lower_route_rules(&p);
        let b = lower_route_rules(&p);
        assert_eq!(a, b, "same plan → identical filters (re-apply = no churn)");
        assert!(behaviorally_equivalent(&a, &b));
        // Primary weight band is above secondary.
        assert!(a[0].weight > a[1].weight);
    }

    #[test]
    fn block_emits_ale_plus_packet_mirror_with_distinct_ids() {
        let ip = Ipv4Addr::new(203, 0, 113, 9);
        let out = lower_route_rules(&plan(vec![block_flow(0, ip)]));
        assert_eq!(out.len(), 2, "block → ALE filter + packet-layer mirror");
        let ale = &out[0];
        let pkt = &out[1];
        assert_eq!(ale.layer, WfpLayerKey::AleAuthConnectV4);
        assert_eq!(ale.action, WfpAction::Block);
        assert_eq!(ale.user_sid.as_deref(), Some("S-1-5-21-A"));
        assert_eq!(pkt.layer, WfpLayerKey::OutboundIpPacketV4);
        assert_eq!(pkt.action, WfpAction::Block);
        assert!(
            pkt.user_sid.is_none(),
            "packet layer carries no ALE user id"
        );
        assert_eq!(ale.weight, pkt.weight, "mirror shares the ALE weight");
        assert_ne!(ale.id, pkt.id, "the pair must have distinct filter ids");
        assert_eq!(ale.weight, BASE_BLOCK);
    }
    /// Two exemptions that differ only by the conditions they carry must get
    /// DIFFERENT ids.
    ///
    /// Seeded on `(sid, layer, action, weight)` alone they collided, the second
    /// add came back `FWP_E_ALREADY_EXISTS` — which the batch counts as success
    /// — and the result was a phantom: recorded installed, absent from WFP,
    /// enforcing nothing. The behavioural oracle cannot see this, because it
    /// ignores ids by construction.
    #[test]
    fn catch_all_ids_separate_filters_that_differ_only_in_their_conditions() {
        let sid = Some("S-1-5-21-1-2-3-1001");
        let base = |disc: &str| {
            derive_catch_all_id(
                sid,
                WfpLayerKey::AleAuthConnectV4,
                WfpAction::Permit,
                100,
                disc,
            )
        };
        assert_ne!(base("1.1.1.1|53"), base("8.8.8.8|53"));
        assert_ne!(base("1.1.1.1|53"), base("1.1.1.1|443"));
        // Same inputs still give the same id — the whole point of deriving it.
        assert_eq!(base("1.1.1.1|53"), base("1.1.1.1|53"));
    }
}
