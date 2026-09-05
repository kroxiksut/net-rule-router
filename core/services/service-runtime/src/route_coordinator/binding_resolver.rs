//! Which live adapter a stored binding means, and what to route out of it.
//!
//! Pure functions over [`AdapterInfo`] and the route table: no `self`, no I/O,
//! no coordinator state. That is what made them the first thing to move out of
//! `route_coordinator.rs` — the interface is the signatures, and there is
//! nothing else to weigh.
//!
//! The identity question is the delicate one and the comments below carry it:
//! the binding stores the GUI's persistent id, `AdapterInfo::stable_id()` uses
//! a different scheme, and a direct compare between them silently matched
//! nothing.

use std::net::Ipv4Addr;

use nrr_platform_api::adapters::AdapterInfo;
use nrr_platform_api::RouteEntry;

use crate::route_codegen::SecondaryRouteTarget;

/// Match a stored route-binding id against a live [`AdapterInfo`].
///
/// The binding stores the GUI **snapshot persistent id**
/// (`win-adapter:{lowercased-adapter-name}`, or the
/// `win-ifindex-mac:{idx}:{MAC}` / `win-ifindex:{idx}` fallbacks) produced by
/// `nrr_platform_api::interface_manager::build_persistent_id`. The
/// low-level `AdapterInfo::stable_id()` uses a DIFFERENT scheme (MAC hex, or
/// the bare adapter name) — so a direct `stable_id()` compare NEVER matched a
/// real binding. That silent mismatch made the coordinator report
/// "secondary adapter not found" for a live, working VPN and route nothing.
/// Reconstruct the persistent id here (keep in sync with `build_persistent_id`).
pub fn adapter_binding_matches(info: &AdapterInfo, bound_id: &str) -> bool {
    identity_matches(
        &info.adapter_name,
        info.index,
        mac_dash(info).as_deref(),
        &info.stable_id(),
        bound_id,
    )
}

/// Same matching rules as [`adapter_binding_matches`], for the wire-shaped
/// [`AdapterEntry`] the IPC layer hands to per-SID consumers (e.g. the
/// Fail-Closed probe) that only ever see the already-enumerated snapshot,
/// not the raw platform-api `AdapterInfo` list.
///
/// `AdapterEntry::physical_address` is colon-separated hex (see
/// `adapter_to_entry`); normalize to the dash form the persistent-id scheme
/// uses before comparing. `AdapterEntry::persistent_id` is populated from
/// `AdapterInfo::stable_id()`, so it is the correct back-compat fallback.
pub fn adapter_entry_binding_matches(
    entry: &nrr_shared::ipc_payloads::AdapterEntry,
    bound_id: &str,
) -> bool {
    let mac_dash = entry
        .physical_address
        .as_deref()
        .map(|mac| mac.replace(':', "-"));
    identity_matches(
        &entry.adapter_name,
        entry.ipv6_if_index,
        mac_dash.as_deref(),
        &entry.persistent_id,
        bound_id,
    )
}

/// Core identity-matching rules, parametrized over the fields both adapter
/// representations in this crate carry. `stable_id_fallback` is the
/// low-level `AdapterInfo::stable_id()` value, kept for bindings persisted
/// before the `win-adapter:`/`win-ifindex-mac:`/`win-ifindex:` scheme
/// existed.
pub(super) fn identity_matches(
    name: &str,
    index: u32,
    mac_dash: Option<&str>,
    stable_id_fallback: &str,
    bound_id: &str,
) -> bool {
    let name = name.trim().to_ascii_lowercase();
    if !name.is_empty() && bound_id.eq_ignore_ascii_case(&format!("win-adapter:{name}")) {
        return true;
    }
    if let Some(mac) = mac_dash {
        if bound_id.eq_ignore_ascii_case(&format!("win-ifindex-mac:{index}:{mac}")) {
            return true;
        }
        // The ifindex-free anchor. A Wi-Fi or Bluetooth adapter that lost power
        // comes back with a new ifindex and sometimes a new GUID, but never a
        // new burned-in MAC — so this is the identity that survives what the
        // other two do not. Only written for adapters whose MAC is independent
        // of their GUID (see `mac_anchor_id`).
        if bound_id.eq_ignore_ascii_case(&format!("win-mac:{mac}")) {
            return true;
        }
    }
    if bound_id.eq_ignore_ascii_case(&format!("win-ifindex:{index}")) {
        return true;
    }
    // Back-compat: a binding stored with the low-level stable_id scheme.
    bound_id.eq_ignore_ascii_case(stable_id_fallback)
}

/// match a live adapter against a binding's current
/// `stable_id` OR any previously-known id the auto-heal folded in. A VPN whose
/// GUID rotated across a reinstall is recognised directly by a prior id,
/// without depending on the friendly-name heal firing again this session.
pub(super) fn binding_matches_live(
    info: &AdapterInfo,
    stable_id: &str,
    known_ids: &[String],
) -> bool {
    adapter_binding_matches(info, stable_id)
        || known_ids.iter().any(|id| adapter_binding_matches(info, id))
}

/// `true` when a whitespace token of an adapter friendly name is purely a
/// version designator (all digits/dots, optionally a leading `v`): "3.0",
/// "4.1", "v3", "2". VPN vendors bump these across reinstalls/upgrades
/// ("hidemy.name VPN OpenVPN Adapter" ↔ "hidemy.name VPN 3.0 OpenVPN
/// Adapter"), so a version token must never participate in identity matching.
pub(super) fn is_version_token(token: &str) -> bool {
    let stripped = token.trim_start_matches(['v', 'V']);
    !stripped.is_empty() && stripped.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// Lower-cased whitespace tokens of a friendly name with version tokens
/// dropped — the stable "family" identity of an adapter description.
pub(super) fn core_tokens(name: &str) -> Vec<String> {
    name.split_whitespace()
        .filter(|t| !is_version_token(t))
        .map(|t| t.to_ascii_lowercase())
        .collect()
}

/// Heuristic name-family match for the stale-GUID auto-heal: `true` when the
/// binding's saved `display_name` and the live adapter's `description` name
/// the SAME adapter family, ignoring version tokens.
///
/// Both sides are reduced to their version-stripped core token set (so
/// "hidemy.name VPN OpenVPN Adapter" and "hidemy.name VPN 3.0 OpenVPN Adapter"
/// reduce to the same family), then matched by **symmetric** containment:
/// either core set is a subset of the other. The earlier implementation
/// required the saved name to be a subset of the live description — a
/// directional test that silently failed the "every other day" case (HW-0708)
/// where the SAVED name carried the version token and the live adapter dropped
/// it (saved "…VPN 3.0 OpenVPN Adapter" vs live "…VPN OpenVPN Adapter"),
/// leaving a live, working VPN reported as "not found among live adapters".
/// Symmetric containment heals both directions. The caller only uses this when
/// EXACTLY ONE usable adapter matches, bounding false positives.
pub(super) fn description_matches_display_name(description: &str, display_name: &str) -> bool {
    let saved = core_tokens(display_name);
    let live = core_tokens(description);
    if saved.is_empty() || live.is_empty() {
        return false;
    }
    saved.iter().all(|t| live.contains(t)) || live.iter().all(|t| saved.contains(t))
}

/// Does `info` still answer to the name the binding was saved under?
///
/// The saved name is whatever the GUI showed, which is the CONNECTION name
/// (`friendly_name`) — a VPN client that renames its connection but ships the
/// stock driver ("TAP-Windows Adapter V9") shares no token with the driver
/// description, so matching the description alone leaves the heal dead exactly
/// where GUID churn makes it necessary.
pub(super) fn adapter_answers_to_saved_name(info: &AdapterInfo, display_name: &str) -> bool {
    description_matches_display_name(&info.description, display_name)
        || description_matches_display_name(&info.friendly_name, display_name)
}

/// Per-kind counts of one codegen's diagnostics, so the log line states which
/// cause fired instead of listing the ones that might have.
#[derive(Default)]
pub(super) struct DiagnosticTally {
    pub(super) hostname_unresolved: usize,
    pub(super) suffix_empty: usize,
    pub(super) zone_empty: usize,
    pub(super) app_rule_address_and_app_not_routed: usize,
    pub(super) app_rule_unobserved: usize,
    pub(super) app_rule_dest_claimed_by_main_link: usize,
    pub(super) app_rule_dest_used_by_other_process: usize,
    pub(super) address_claimed_by_main_link: usize,
    pub(super) primary_exceptions_unavailable: usize,
}

pub(super) fn diagnostic_tally(
    diagnostics: &[crate::route_codegen::RouteCodegenDiagnostic],
) -> DiagnosticTally {
    use crate::route_codegen::RouteCodegenDiagnostic as D;
    let mut t = DiagnosticTally::default();
    for d in diagnostics {
        match d {
            D::HostnameUnresolved { .. } => t.hostname_unresolved += 1,
            D::SuffixEmpty { .. } => t.suffix_empty += 1,
            D::ZoneEmpty { .. } => t.zone_empty += 1,
            D::AppRuleAddressAndAppNotRouted { .. } => t.app_rule_address_and_app_not_routed += 1,
            D::AppRuleUnobserved { .. } => t.app_rule_unobserved += 1,
            D::AppRuleDestinationClaimedByMainLink { .. } => {
                t.app_rule_dest_claimed_by_main_link += 1
            }
            D::AppRuleDestinationUsedByOtherProcess { .. } => {
                t.app_rule_dest_used_by_other_process += 1
            }
            D::AddressClaimedByMainLink { count, .. } => t.address_claimed_by_main_link += count,
            D::PrimaryExceptionsUnavailable => t.primary_exceptions_unavailable += 1,
        }
    }
    t
}

/// Dash-separated upper-case MAC, the spelling every persistent-id form uses.
pub(super) fn mac_dash(info: &AdapterInfo) -> Option<String> {
    info.mac.map(|mac| {
        mac.iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join("-")
    })
}

/// `true` when the MAC identifies the adapter independently of its GUID.
///
/// A tunnel adapter derives its MAC from its own GUID — a live TAP-Windows
/// instance was observed as MAC `00:FF:0C:93:B1:CC` under GUID
/// `{0C93B1CC-9269-4F48-B0E8-EEE8918BBECC}` — so the two rotate together on
/// every reconnect and the MAC carries no identity the GUID did not already
/// carry. Anchoring on it would either never match or, worse, match whatever
/// instance the client created last. Interface TYPE cannot make this call:
/// TAP reports itself as Ethernet.
pub(super) fn mac_is_independent_identity(info: &AdapterInfo) -> bool {
    let Some(mac) = info.mac else {
        return false;
    };
    if nrr_platform_api::adapters::description_matches_virtual_software(&info.description) {
        return false;
    }
    let guid_head: String = info
        .adapter_name
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(8)
        .collect();
    let mac_tail: String = mac[2..].iter().map(|b| format!("{b:02x}")).collect();
    !guid_head.eq_ignore_ascii_case(&mac_tail)
}

/// The MAC-only identity to remember for a binding, or `None` when this
/// adapter's MAC is not an identity of its own (see
/// [`mac_is_independent_identity`]).
pub(super) fn mac_anchor_id(info: &AdapterInfo) -> Option<String> {
    if !mac_is_independent_identity(info) {
        return None;
    }
    mac_dash(info).map(|mac| format!("win-mac:{mac}"))
}

/// The name to store for an adapter: the connection name the GUI lists, with
/// the driver description as the fallback.
pub(super) fn preferred_display_name(info: &AdapterInfo) -> &str {
    let friendly = info.friendly_name.trim();
    if friendly.is_empty() {
        &info.description
    } else {
        friendly
    }
}

/// Derive a usable next-hop for a secondary adapter that exposes **no**
/// classic default gateway. OpenVPN / WireGuard TUN links commonly install
/// split-default routes (`0.0.0.0/1` + `128.0.0.0/1`, or a plain
/// `0.0.0.0/0`) pointing at the tunnel **peer** instead of setting a
/// gateway on the adapter — so `GetAdaptersAddresses` reports an empty
/// gateway list and the adapter-gateway lookup finds nothing, even though
/// the link is up and routing fine. We reuse that peer as the next-hop for
/// our `/32` overlays so matched traffic travels exactly like the VPN's own
/// redirected traffic. (Observed on a live hidemy.name OpenVPN link:
/// `0.0.0.0/1 -> 10.91.192.1` with no adapter gateway.)
///
/// Default-style routes on `ifindex` with a real (non-unspecified,
/// non-loopback) next-hop are preferred (`/0`, then the `/1` halves, then
/// lowest metric); ANY other gateway-style route on the interface is a
/// last resort — on a point-to-point tunnel every such route
/// names the one peer, which recovers the next-hop after the catch-alls
/// were stripped and a restart lost the in-memory cache. Returns `None`
/// when the interface carries only on-link routes (host-only virtual
/// adapter, or a tunnel whose client has not yet installed any route).
/// The single implementation lives in `nrr-platform-api` so the interface
/// enumeration reports exactly the next-hop this layer would route through —
/// otherwise the GUI could call an adapter unusable that the router uses
/// happily (or the reverse).
pub(super) fn derive_secondary_next_hop(routes: &[RouteEntry], ifindex: u32) -> Option<Ipv4Addr> {
    nrr_platform_api::interface_rows::derive_forwarding_next_hop(routes, ifindex)
}

/// Derive the **primary** routing target (gateway + interface) from the OS
/// default route, for when the user bound only a secondary (VPN) adapter.
///
/// Mode-A's `/2` counter-overlay (so unmatched traffic egresses the real link
/// instead of the tunnel) and mode-B's exception `/32`s both route via the
/// primary gateway. Requiring the user to *also* bind a primary just for this
/// is a footgun — "direct" silently kept unmatched traffic on the secondary
/// adapter. So when no primary is explicitly bound we fall back to the real
/// internet gateway: the lowest-metric `0.0.0.0/0` whose interface is NOT the
/// secondary and whose next-hop is a real address (the OS default-route
/// anchor the secondary adapter leaves on the physical NIC). Returns `None`
/// when no such default route exists (e.g. a
/// VPN that replaced `/0` itself) — the caller then logs the actionable gap.
pub(super) fn derive_primary_target(
    routes: &[RouteEntry],
    secondary_ifindex: u32,
) -> Option<SecondaryRouteTarget> {
    let mut best: Option<(u32, Ipv4Addr, u32)> = None; // (metric, gateway, ifindex)
    for r in routes {
        if r.interface_index == secondary_ifindex {
            continue;
        }
        if !(r.destination.is_unspecified() && r.prefix_length == 0) {
            continue;
        }
        let nh = r.next_hop;
        if nh.is_unspecified() || nh.is_loopback() {
            continue;
        }
        let cand = (r.metric, nh, r.interface_index);
        best = Some(match best {
            Some(b) if b.0 <= cand.0 => b,
            _ => cand,
        });
    }
    best.map(|(_, gateway, interface_index)| SecondaryRouteTarget {
        gateway,
        interface_index,
    })
}
