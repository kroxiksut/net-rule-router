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
//!   [`RouteEntry`]s (`route_codegen::generate_routes`).

use std::net::{Ipv4Addr, Ipv6Addr};

use nrr_platform_api::enforcement::{
    AppScope, Coverage, DstMatch, EgressConstraint, EgressRef, EnforcementPlan, FlowRule, L4Proto,
    PrecedenceClass, Verdict,
};
use nrr_platform_api::types::{WfpAction, WfpFilterId, WfpFilterSpec, WfpLayerKey};
use nrr_platform_api::RouteEntry;
use nrr_shared::RouteRole;

// Weight base bands, mirrored from the current `wfp_codegen` so the RELATIVE
// arbitration order is identical (the absolute values need not be — the
// behavioral oracle ignores literal weights, but preserves their order):
// primary route rules outrank secondary; the role-independent Block band sits
// above both.
const BASE_PRIMARY: u64 = 0x0020_0000;
const BASE_SECONDARY: u64 = 0x0010_0000;
const BASE_BLOCK: u64 = 0x0060_0000;
// Kill-switch bands, mirrored from `killswitch_codegen`: the egress-conditional
// permit sits above its unconditional block (both above the route-rule bands),
// so "permit only while egressing the secondary adapter, else block" arbitrates
// correctly.
const KILLSWITCH_PERMIT_BASE: u64 = 0x0040_0000;
const KILLSWITCH_BLOCK_BASE: u64 = 0x0030_0000;
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
    plan.flows.iter().flat_map(lower_flow).collect()
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
/// | `KillSwitchPermit` | `OnlyVia(Secondary)` | `ConnectOnly` | `HostV4` | **ALE IP pair** — a permit carrying the secondary `local_interface_luid` (`KILLSWITCH_PERMIT_BASE + ordinal`) over a `Block` (`KILLSWITCH_BLOCK_BASE + ordinal`) at `AleAuthConnectV4` (4a). |
/// | `KillSwitchPermit` | `OnlyVia(Secondary)` | `ConnectOnly` | `Program` | **ALE app pair** — the same, keyed on `ALE_APP_ID` instead of a remote IP (4d). |
/// | `KillSwitchPermit` | `OnlyVia(Secondary)` | `AllPackets` | `HostV4` | **packet pair** — the egress-conditional permit-over-block at `OutboundIpPacketV4`, narrowed to `flow.protocol`, `user_sid = None` (4b). |
/// | `KillSwitchPermit` | `Any` | `AllPackets` | `HostV4` | **packet permit** — a lone `Permit` (`PACKET_PERMIT_BASE + ordinal`) letting an UN-selected protocol escape the block-all (4b). |
/// | `KillSwitchBlock` | — | `ConnectOnly` | `HostV4` | **ALE IP block** (`KILLSWITCH_BLOCK_BASE + ordinal`), narrowed to `flow.protocol` (4d fail-closed). |
/// | `KillSwitchBlock` | — | `ConnectOnly` | `Program` | **ALE app block** (proto-agnostic) (4d fail-closed). |
/// | `KillSwitchBlock` | — | `AllPackets` | `HostV4` | **packet block** (`PACKET_BLOCK_BASE + ordinal`) (4d fail-closed). |
///
/// The ALE IP/app pairs are proto-agnostic; the packet flows and fail-closed ALE
/// blocks carry the concrete [`L4Proto`], mapped to the WFP `ip_protocol` number.
/// The neutral `ordinal` already folds the per-destination `idx * 16` slot window
/// (packet flows) or is the plain destination/app index, so every weight is just
/// `band + ordinal` — reproducing the current codegen's exact weights, hence
/// identical arbitration order.
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
                        out.push(ale_app_block(pat, KILLSWITCH_BLOCK_BASE + ord, user_sid));
                    }
                    // 4a — ALE per-destination egress-conditional pair (proto-agnostic).
                    (
                        EgressConstraint::OnlyVia(EgressRef::Secondary),
                        Coverage::ConnectOnly,
                        DstMatch::HostV4(ip),
                        None,
                    ) => {
                        out.push(ale_egress_permit(
                            ip,
                            secondary_luid,
                            KILLSWITCH_PERMIT_BASE + ord,
                            user_sid.clone(),
                            proto,
                        ));
                        // Block half: drop `ip` whenever the permit misses.
                        out.push(make_host_filter(
                            WfpLayerKey::AleAuthConnectV4,
                            WfpAction::Block,
                            ip,
                            KILLSWITCH_BLOCK_BASE + ord,
                            user_sid,
                        ));
                    }
                    // 4b — packet-layer egress-conditional pair (ICMP/IGMP/GRE/ESP/Other).
                    (
                        EgressConstraint::OnlyVia(EgressRef::Secondary),
                        Coverage::AllPackets,
                        DstMatch::HostV4(ip),
                        None,
                    ) => {
                        out.push(packet_egress_permit(
                            ip,
                            secondary_luid,
                            PACKET_EXEMPT_BASE + ord,
                            proto,
                        ));
                        out.push(packet_block(ip, PACKET_BLOCK_BASE + ord, proto));
                    }
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
                        out.push(ale_app_block(pat, KILLSWITCH_BLOCK_BASE + ord, user_sid));
                    }
                    // per-destination ALE block (narrowed to the ALE protocol).
                    (Coverage::ConnectOnly, DstMatch::HostV4(ip), None) => {
                        out.push(ale_ip_block(
                            ip,
                            proto,
                            KILLSWITCH_BLOCK_BASE + ord,
                            user_sid,
                        ));
                    }
                    // per-destination packet block.
                    (Coverage::AllPackets, DstMatch::HostV4(ip), None) => {
                        out.push(packet_block(ip, PACKET_BLOCK_BASE + ord, proto));
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    out
}

/// Lower the DoH/DoT lockdown plan
/// ([`enforcement_planner::plan_doh_dot_block`]) to WFP filters. Each
/// [`PrecedenceClass::DohBlock`] flow becomes one ALE-connect `Block` narrowed to
/// `(remote_ip?, dst_port, protocol)` at `DOH_BLOCK_BASE + ordinal` — reproducing
/// `killswitch_codegen::doh_dot_block_filters` exactly.
pub fn lower_doh_dot_block(plan: &EnforcementPlan) -> Vec<WfpFilterSpec> {
    let mut out = Vec::new();
    for flow in &plan.flows {
        if flow.precedence.class != PrecedenceClass::DohBlock || flow.verdict != Verdict::Block {
            continue;
        }
        let user_sid = flow.principal.0.as_ref().map(|p| p.as_stored().to_string());
        let proto = flow.flow.protocol.map(l4proto_to_ip_number);
        let remote_ip = match flow.flow.dst {
            DstMatch::HostV4(ip) => Some(ip),
            DstMatch::Any => None,
            _ => continue, // DoH lockdown only emits HostV4 / Any
        };
        let weight = DOH_BLOCK_BASE + u64::from(flow.precedence.ordinal);
        out.push(doh_port_block(
            remote_ip,
            flow.flow.dst_port,
            proto,
            weight,
            user_sid,
        ));
    }
    out
}

/// ALE-connect `Block` narrowed to `(remote_ip?, port, proto)`. Mirrors
/// `killswitch_codegen::doh_port_block`.
fn doh_port_block(
    remote_ip: Option<Ipv4Addr>,
    remote_port: Option<u16>,
    proto: Option<u8>,
    weight: u64,
    user_sid: Option<String>,
) -> WfpFilterSpec {
    // Id derivation must not collide with `ale_ip_block` (same layer/action/ip):
    // include the port in the seed via a dedicated id. Reuse the IP-keyed derive
    // when an IP is present, else derive from the unspecified address.
    let id = derive_filter_id(
        user_sid.as_deref(),
        WfpLayerKey::AleAuthConnectV4,
        WfpAction::Block,
        remote_ip.unwrap_or(Ipv4Addr::UNSPECIFIED),
        weight,
    );
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip,
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

/// ALE-connect per-destination `Block`, narrowed to `proto`. Mirrors
/// `killswitch_codegen::ale_block` (the fail-closed per-IP block).
fn ale_ip_block(
    ip: Ipv4Addr,
    proto: Option<u8>,
    weight: u64,
    user_sid: Option<String>,
) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip: Some(ip),
        remote_port: None,
        weight,
        id: derive_filter_id(
            user_sid.as_deref(),
            WfpLayerKey::AleAuthConnectV4,
            WfpAction::Block,
            ip,
            weight,
        ),
        user_sid,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: proto,
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

/// ALE-connect egress-conditional `Permit` — allow `ip` only while the flow
/// egresses `luid`. Mirrors `killswitch_codegen::permit_via_secondary`.
fn ale_egress_permit(
    ip: Ipv4Addr,
    luid: u64,
    weight: u64,
    user_sid: Option<String>,
    proto: Option<u8>,
) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Permit,
        remote_ip: Some(ip),
        remote_port: None,
        weight,
        id: derive_filter_id(
            user_sid.as_deref(),
            WfpLayerKey::AleAuthConnectV4,
            WfpAction::Permit,
            ip,
            weight,
        ),
        user_sid,
        app_pattern: None,
        local_interface_luid: Some(luid),
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: proto,
    }
}

/// Below-ALE egress-conditional `Permit` — allow `ip` (for `proto`) only while
/// the flow egresses `luid`. `user_sid = None` (no ALE user id below the ALE
/// layers). Mirrors `killswitch_codegen::packet_egress_permit`. A
/// protocol-narrowed filter MUST live at `OUTBOUND_TRANSPORT_V4` — the packet
/// layer has no `FWPM_CONDITION_IP_PROTOCOL` and rejects it with
/// `FWP_E_CONDITION_NOT_FOUND`.
fn packet_egress_permit(ip: Ipv4Addr, luid: u64, weight: u64, proto: Option<u8>) -> WfpFilterSpec {
    let layer = below_ale_layer_for(proto);
    WfpFilterSpec {
        layer,
        action: WfpAction::Permit,
        remote_ip: Some(ip),
        remote_port: None,
        weight,
        id: derive_filter_id(None, layer, WfpAction::Permit, ip, weight),
        user_sid: None,
        app_pattern: None,
        local_interface_luid: Some(luid),
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: proto,
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

/// Below-ALE unconditional `Block` for `ip` (narrowed to `proto`).
/// `user_sid = None`. Mirrors `killswitch_codegen::packet_block`. Layer picked
/// by [`below_ale_layer_for`].
fn packet_block(ip: Ipv4Addr, weight: u64, proto: Option<u8>) -> WfpFilterSpec {
    let layer = below_ale_layer_for(proto);
    WfpFilterSpec {
        layer,
        action: WfpAction::Block,
        remote_ip: Some(ip),
        remote_port: None,
        weight,
        id: derive_filter_id(None, layer, WfpAction::Block, ip, weight),
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: proto,
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
            remote_port: None,
            weight,
            id: derive_catch_all_id(
                user_sid.as_deref(),
                WfpLayerKey::AleAuthConnectV4,
                WfpAction::Block,
                weight,
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
/// Fails OPEN on `secondary_luid == 0` (the blanket permit's egress condition
/// would never match, black-holing everything) — like the current codegen. The
/// `no server exemptions` / `no protocol selected` safety valves are the planner's
/// concern (it emits no flows), so they need no handling here.
pub fn lower_catch_all_kill_switch(
    plan: &EnforcementPlan,
    secondary_luid: u64,
) -> Vec<WfpFilterSpec> {
    if secondary_luid == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for flow in &plan.flows {
        if !matches!(
            flow.precedence.class,
            PrecedenceClass::CatchAllExempt | PrecedenceClass::CatchAllBlock
        ) {
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
            // 4d — DNS-over-primary exemptions are port-scoped (remote 53).
            remote_port: flow.flow.dst_port,
            weight,
            id: derive_catch_all_id(user_sid.as_deref(), layer, action, weight),
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

/// A resolved egress target for route lowering — the concrete gateway + interface
/// index an [`EgressRef`] maps to. This is the route analog of the kill-switch
/// LUID: a lowering-time, per-OS binding the neutral plan never carries.
#[derive(Clone, Copy, Debug)]
pub struct RouteTarget {
    pub gateway: Ipv4Addr,
    pub interface_index: u32,
}

/// Lower the [`RouteIntent`](nrr_platform_api::enforcement::RouteIntent)s of `plan`
/// into system route-table [`RouteEntry`]s — the Windows half of
/// `route_codegen::generate_routes` (the routing mechanism; WFP is the blocking
/// one). Each intent's [`EgressRef`] is resolved to its [`RouteTarget`]
/// (`Secondary` → `secondary`, `Primary` → `primary` — skipped if the caller has
/// no primary target, matching the codegen's `PrimaryExceptionsUnavailable`), and
/// its [`DstMatch`] to `(destination, prefix_length)` (`HostV4` → `/32`, `SubnetV4`
/// → the overlay prefix). `is_ours = true` and `metric` come straight from the
/// intent; only the `Main` table is produced on Windows. Ipv6 route intents (none
/// today) are skipped.
pub fn lower_routes(
    plan: &EnforcementPlan,
    secondary: RouteTarget,
    primary: Option<RouteTarget>,
) -> Vec<RouteEntry> {
    let mut out = Vec::new();
    for intent in &plan.routes {
        let target = match intent.egress {
            EgressRef::Secondary => secondary,
            EgressRef::Primary => match primary {
                Some(p) => p,
                None => continue,
            },
            EgressRef::Adapter(_) => continue,
        };
        let (destination, prefix_length) = match intent.dst {
            DstMatch::HostV4(ip) => (ip, 32u8),
            DstMatch::SubnetV4 { net, prefix } => (net, prefix),
            // Windows routes are IPv4-only today; skip anything else.
            _ => continue,
        };
        out.push(RouteEntry {
            destination,
            prefix_length,
            next_hop: target.gateway,
            interface_index: target.interface_index,
            metric: intent.metric,
            is_ours: true,
            table: intent.table.clone(),
        });
    }
    out
}

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

/// Deterministic id for a catch-all filter. `(layer, weight)` is unique within a
/// catch-all set (each band uses each weight once), so this is stable + distinct;
/// the oracle ignores ids regardless.
fn derive_catch_all_id(
    sid: Option<&str>,
    layer: WfpLayerKey,
    action: WfpAction,
    weight: u64,
) -> WfpFilterId {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let seed = format!(
        "catchall|{}|{}|{}|{weight}",
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
        assert_eq!(f.remote_ip, Some(Ipv4Addr::new(203, 0, 113, 5)));
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
}
