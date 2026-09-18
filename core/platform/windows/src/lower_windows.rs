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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nrr_platform_api::enforcement::{
    AppScope, Coverage, DstMatch, EgressConstraint, EgressRef, EnforcementPlan, FlowRule, L4Proto,
    PrecedenceClass, Verdict,
};
use nrr_platform_api::types::{WfpAction, WfpFilterId, WfpFilterSpec, WfpLayerKey};
use nrr_platform_api::wfp_slotting::{pack_both, pack_v4, FamilyChunk, V4SlotChunk};
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

mod app_and_dns;
mod catch_all;
mod flows;
mod ids;
mod kill_switch;
mod plan;
mod route_rules;

pub use app_and_dns::*;
pub use catch_all::*;
use flows::*;
pub use ids::*;
pub use kill_switch::*;
pub use plan::*;
pub use route_rules::*;

#[cfg(test)]
mod tests;
